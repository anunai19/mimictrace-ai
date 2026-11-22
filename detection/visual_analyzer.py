import warnings
from io import BytesIO

from PIL import Image, ImageOps, UnidentifiedImageError

from detection.evidence import EvidenceRecord
from detection.visual_catalog import get_catalog
from detection.visual_matcher import compute_image_hashes, hamming_distance

MAX_LOGO_IMAGE_BYTES = 5 * 1024 * 1024
MAX_LOGO_WIDTH = 4096
MAX_LOGO_HEIGHT = 4096
MAX_LOGO_PIXELS = 12_000_000
MAX_ANALYSIS_DIMENSION = 512

_FORMAT_METADATA = {
    "PNG": ("image/png", {"png"}),
    "JPEG": ("image/jpeg", {"jpg", "jpeg"}),
}


class InvalidLogoImageError(ValueError):
    """The uploaded content is not a supported, valid logo crop."""


class LogoImageLimitError(ValueError):
    """The uploaded image exceeds a configured processing limit."""


def _record(status, availability, observation, uncertainty):
    return EvidenceRecord(
        source="visual.logo_crop",
        observation={"availability": availability, **observation},
        status=status,
        uncertainty=uncertainty,
    )


def _validate_declared_metadata(image_format, filename, content_type):
    expected_mime, expected_extensions = _FORMAT_METADATA[image_format]
    if content_type is not None:
        if not isinstance(content_type, str):
            raise InvalidLogoImageError()
        declared_mime = content_type.split(";", 1)[0].strip().lower()
        if declared_mime != expected_mime:
            raise InvalidLogoImageError()
    if filename is not None:
        if not isinstance(filename, str):
            raise InvalidLogoImageError()
        basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if "." not in basename:
            raise InvalidLogoImageError()
        extension = basename.rsplit(".", 1)[-1].lower()
        if extension not in expected_extensions:
            raise InvalidLogoImageError()


def _validate_dimensions(image):
    width, height = image.size
    if (
        not isinstance(width, int)
        or not isinstance(height, int)
        or width < 1
        or height < 1
    ):
        raise InvalidLogoImageError()
    if (
        width > MAX_LOGO_WIDTH
        or height > MAX_LOGO_HEIGHT
        or width * height > MAX_LOGO_PIXELS
    ):
        raise LogoImageLimitError()
    return width, height


def _decode_and_preprocess(image_bytes, filename, content_type):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(image_bytes)) as image:
                image_format = image.format
                if image_format not in _FORMAT_METADATA:
                    raise InvalidLogoImageError()
                _validate_declared_metadata(image_format, filename, content_type)
                _validate_dimensions(image)
                if getattr(image, "n_frames", 1) != 1:
                    raise InvalidLogoImageError()
                image.verify()

            with Image.open(BytesIO(image_bytes)) as image:
                if image.format != image_format:
                    raise InvalidLogoImageError()
                _validate_dimensions(image)
                if getattr(image, "n_frames", 1) != 1:
                    raise InvalidLogoImageError()
                image.load()
                oriented = ImageOps.exif_transpose(image)
                try:
                    normalized_width, normalized_height = _validate_dimensions(
                        oriented
                    )
                    if "A" in oriented.getbands() or "transparency" in oriented.info:
                        rgba = oriented.convert("RGBA")
                        background = Image.new(
                            "RGBA",
                            rgba.size,
                            (255, 255, 255, 255),
                        )
                        background.alpha_composite(rgba)
                        normalized = background.convert("RGB")
                        rgba.close()
                        background.close()
                    else:
                        normalized = oriented.convert("RGB")
                    try:
                        normalized.thumbnail(
                            (MAX_ANALYSIS_DIMENSION, MAX_ANALYSIS_DIMENSION),
                            Image.Resampling.LANCZOS,
                        )
                        # Extract 64-bit pHash and dHash while normalized canvas is in memory
                        query_phash, query_dhash = compute_image_hashes(normalized)

                        return {
                            "decoded_format": image_format,
                            "normalized_width": normalized_width,
                            "normalized_height": normalized_height,
                            "analysis_width": normalized.width,
                            "analysis_height": normalized.height,
                            "analysis_color_mode": "RGB",
                            "query_phash": query_phash,
                            "query_dhash": query_dhash,
                        }
                    finally:
                        normalized.close()
                finally:
                    if oriented is not image:
                        oriented.close()
    except LogoImageLimitError:
        raise
    except InvalidLogoImageError:
        raise
    except (Image.DecompressionBombWarning, Image.DecompressionBombError):
        raise LogoImageLimitError() from None
    except (UnidentifiedImageError, OSError, EOFError, SyntaxError, ValueError):
        raise InvalidLogoImageError() from None


def analyze_logo_crop(image_bytes=None, *, filename=None, content_type=None, catalog=None):
    """Validate, preprocess, and compare an uploaded logo crop without external access."""
    base_uncertainty = [
        "The image was supplied by the user and was not verified as a capture from the submitted URL.",
        "Image validation and resizing do not identify a brand or establish impersonation.",
        "Perceptual hashing measures visual shape resemblance and does not establish trademark infringement or brand ownership.",
        "Input limits reduce processing work but do not provide hard CPU or memory isolation.",
    ]
    if image_bytes is None:
        return _record(
            "not_run",
            "no_image_uploaded",
            {"input_type": "user_uploaded_logo_crop"},
            base_uncertainty,
        )
    if not isinstance(image_bytes, bytes) or not image_bytes:
        raise InvalidLogoImageError()
    if len(image_bytes) > MAX_LOGO_IMAGE_BYTES:
        raise LogoImageLimitError()

    observation = _decode_and_preprocess(
        image_bytes,
        filename,
        content_type,
    )
    observation["input_type"] = "user_uploaded_logo_crop"

    active_catalog = catalog if catalog is not None else get_catalog()

    if not active_catalog.is_available:
        observation["catalog_brands_configured"] = active_catalog.configured_brands_count
        observation["calibration_state"] = None
        observation["candidate_brand"] = None
        observation["reference_variant"] = None
        observation["match_result"] = None
        observation["evaluations"] = []

        uncertainty = list(base_uncertainty)
        uncertainty.append(
            "Extracted query hashes represent local image descriptors only; "
            "no comparison was performed because the reference catalog is unavailable."
        )
        if active_catalog.failure_reason == "empty_catalog":
            uncertainty.append("No reference-image catalog entries are configured, so no comparison was performed.")

        failure_reason = active_catalog.failure_reason or "catalog_unavailable"
        return _record(
            "unavailable",
            failure_reason,
            observation,
            uncertainty,
        )

    # Active catalog with >= 1 brand available
    query_phash = observation["query_phash"]
    query_dhash = observation["query_dhash"]

    evaluations = []
    for brand, variant in active_catalog.get_all_variants():
        p_dist = hamming_distance(query_phash, variant.phash_64)
        d_dist = hamming_distance(query_dhash, variant.dhash_64)
        evaluations.append({
            "brand": brand.brand_name,
            "canonical_domain": brand.canonical_domain,
            "variant_id": variant.variant_id,
            "phash_distance": p_dist,
            "dhash_distance": d_dist,
        })

    evaluations.sort(key=lambda item: (item["phash_distance"] + item["dhash_distance"], item["phash_distance"]))

    observation["catalog_brands_configured"] = active_catalog.configured_brands_count
    observation["calibration_state"] = active_catalog.calibration_status
    observation["candidate_brand"] = None
    observation["reference_variant"] = None
    observation["match_result"] = None
    observation["evaluations"] = evaluations

    uncertainty = list(base_uncertainty)
    uncertainty.append(
        "Visual comparison is operating in uncalibrated experimental mode; "
        "raw distance metrics are provided for observation only without a match verdict."
    )
    if active_catalog.mode == "hash_only":
        uncertainty.append(
            "Reference hashes are precomputed and cannot be independently verified against raster assets at runtime."
        )
    uncertainty.append(
        "Visual similarity alone does not establish brand impersonation, authorization, or malicious intent."
    )

    return _record(
        "observed",
        "available",
        observation,
        uncertainty,
    )
