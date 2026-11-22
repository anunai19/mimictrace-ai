import hashlib
import json
import logging
import os
import re
import threading
import warnings
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PIL import Image, ImageOps, UnidentifiedImageError

from detection.visual_matcher import compute_image_hashes

logger = logging.getLogger(__name__)

HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{16}$")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
SUPPORTED_MODES = frozenset({"hash_only", "asset_backed"})
SUPPORTED_CALIBRATION_STATUSES = frozenset({"uncalibrated", "calibrated"})

MAX_CATALOG_ASSET_BYTES = 2 * 1024 * 1024
MAX_CATALOG_ASSET_WIDTH = 2048
MAX_CATALOG_ASSET_HEIGHT = 2048
MAX_CATALOG_ASSET_PIXELS = 4_000_000
MAX_CATALOG_ANALYSIS_DIMENSION = 512

DEFAULT_MANIFEST_PATH = (
    Path(__file__).resolve().parent / "reference_catalog" / "manifest.json"
)


class CatalogState:
    READY = "ready"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class VisualVariant:
    variant_id: str
    phash_64: str
    dhash_64: str
    asset_path: Optional[str] = None
    sha256: Optional[str] = None
    aspect_ratio: Optional[float] = None


@dataclass(frozen=True)
class VisualBrand:
    brand_id: str
    brand_name: str
    canonical_domain: str
    variants: Tuple[VisualVariant, ...]


@dataclass(frozen=True)
class CatalogInstance:
    state: str
    failure_reason: Optional[str]
    mode: Optional[str]
    version: Optional[str]
    calibration_status: Optional[str]
    brands: Dict[str, VisualBrand]

    @property
    def is_available(self) -> bool:
        return self.state == CatalogState.READY

    @property
    def configured_brands_count(self) -> int:
        return len(self.brands)

    def get_brand(self, brand_id: str) -> Optional[VisualBrand]:
        return self.brands.get(brand_id)

    def get_all_variants(self) -> List[Tuple[VisualBrand, VisualVariant]]:
        results: List[Tuple[VisualBrand, VisualVariant]] = []
        for brand in self.brands.values():
            for variant in brand.variants:
                results.append((brand, variant))
        return results


def _unavailable(reason: str) -> CatalogInstance:
    return CatalogInstance(
        state=CatalogState.UNAVAILABLE,
        failure_reason=reason,
        mode=None,
        version=None,
        calibration_status=None,
        brands={},
    )


def _validate_hash(value: str) -> bool:
    if not isinstance(value, str):
        return False
    if "placeholder" in value.lower() or "not_real" in value.lower():
        return False
    return bool(HASH_PATTERN.match(value))


def _compute_file_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _preprocess_and_compute_asset_hashes(asset_path: Path) -> Tuple[str, str]:
    if asset_path.stat().st_size > MAX_CATALOG_ASSET_BYTES:
        raise ValueError("asset_limit_exceeded")

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with open(asset_path, "rb") as f:
            raw_bytes = f.read()

        with Image.open(BytesIO(raw_bytes)) as image:
            if image.format not in ("PNG", "JPEG"):
                raise ValueError("corrupt_asset")
            width, height = image.size
            if (
                width < 1
                or height < 1
                or width > MAX_CATALOG_ASSET_WIDTH
                or height > MAX_CATALOG_ASSET_HEIGHT
                or width * height > MAX_CATALOG_ASSET_PIXELS
            ):
                raise ValueError("asset_limit_exceeded")
            if getattr(image, "n_frames", 1) != 1:
                raise ValueError("corrupt_asset")
            image.verify()

        with Image.open(BytesIO(raw_bytes)) as image:
            image.load()
            oriented = ImageOps.exif_transpose(image)
            try:
                width, height = oriented.size
                if (
                    width < 1
                    or height < 1
                    or width > MAX_CATALOG_ASSET_WIDTH
                    or height > MAX_CATALOG_ASSET_HEIGHT
                    or width * height > MAX_CATALOG_ASSET_PIXELS
                ):
                    raise ValueError("asset_limit_exceeded")
                if "A" in oriented.getbands() or "transparency" in oriented.info:
                    rgba = oriented.convert("RGBA")
                    background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
                    background.alpha_composite(rgba)
                    normalized = background.convert("RGB")
                    rgba.close()
                    background.close()
                else:
                    normalized = oriented.convert("RGB")

                try:
                    normalized.thumbnail(
                        (MAX_CATALOG_ANALYSIS_DIMENSION, MAX_CATALOG_ANALYSIS_DIMENSION),
                        Image.Resampling.LANCZOS,
                    )
                    return compute_image_hashes(normalized)
                finally:
                    normalized.close()
            finally:
                if oriented is not image:
                    oriented.close()


def load_catalog(manifest_path: Optional[Path] = None) -> CatalogInstance:
    path = Path(manifest_path) if manifest_path else DEFAULT_MANIFEST_PATH

    if not path.is_file():
        logger.warning("Visual catalog manifest does not exist: %s", path)
        return _unavailable("manifest_missing")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as err:
        logger.warning("Failed to parse visual catalog manifest: %s", err)
        return _unavailable("invalid_manifest")

    if not isinstance(data, dict):
        return _unavailable("invalid_manifest")

    version = data.get("catalog_version")
    if not isinstance(version, str) or not version.strip():
        return _unavailable("invalid_manifest")

    mode = data.get("mode")
    if mode not in SUPPORTED_MODES:
        return _unavailable("unsupported_mode")

    calibration_status = data.get("calibration_status")
    if calibration_status not in SUPPORTED_CALIBRATION_STATUSES:
        return _unavailable("invalid_calibration_status")

    brands_data = data.get("brands")
    if not isinstance(brands_data, dict) or len(brands_data) == 0:
        return _unavailable("empty_catalog")

    manifest_dir = path.parent
    parsed_brands: Dict[str, VisualBrand] = {}

    for brand_id, brand_info in brands_data.items():
        if not isinstance(brand_id, str) or not brand_id.strip():
            return _unavailable("invalid_manifest")
        if not isinstance(brand_info, dict):
            return _unavailable("invalid_manifest")

        brand_name = brand_info.get("brand_name")
        canonical_domain = brand_info.get("canonical_domain")
        raw_variants = brand_info.get("variants")

        if (
            not isinstance(brand_name, str)
            or not brand_name.strip()
            or not isinstance(canonical_domain, str)
            or not canonical_domain.strip()
            or not isinstance(raw_variants, list)
            or len(raw_variants) == 0
        ):
            return _unavailable("invalid_manifest")

        parsed_variants: List[VisualVariant] = []

        for variant_info in raw_variants:
            if not isinstance(variant_info, dict):
                return _unavailable("invalid_manifest")

            variant_id = variant_info.get("variant_id")
            if not isinstance(variant_id, str) or not variant_id.strip():
                return _unavailable("invalid_manifest")

            hashes = variant_info.get("precomputed_hashes")
            if not isinstance(hashes, dict):
                return _unavailable("invalid_manifest")

            phash = hashes.get("phash_64")
            dhash = hashes.get("dhash_64")

            if not _validate_hash(phash) or not _validate_hash(dhash):
                return _unavailable("invalid_hash_data")

            asset_path = variant_info.get("asset_path")
            sha256 = variant_info.get("sha256")
            aspect_ratio = variant_info.get("aspect_ratio")

            if aspect_ratio is not None and not isinstance(aspect_ratio, (int, float)):
                return _unavailable("invalid_manifest")

            if mode == "asset_backed":
                if not isinstance(asset_path, str) or not asset_path.strip():
                    return _unavailable("invalid_manifest")
                if not isinstance(sha256, str) or not SHA256_PATTERN.match(sha256):
                    return _unavailable("invalid_manifest")

                full_asset_path = (manifest_dir / asset_path).resolve()

                # Boundary check: ensure asset is inside manifest directory hierarchy
                try:
                    full_asset_path.relative_to(manifest_dir.resolve())
                except ValueError:
                    return _unavailable("path_traversal_detected")

                if not full_asset_path.is_file():
                    logger.warning("Catalog asset file missing: %s", full_asset_path)
                    return _unavailable("asset_missing")

                try:
                    computed_sha256 = _compute_file_sha256(full_asset_path)
                    if computed_sha256 != sha256.lower():
                        logger.warning(
                            "Catalog asset SHA-256 mismatch for %s: expected %s, got %s",
                            variant_id,
                            sha256,
                            computed_sha256,
                        )
                        return _unavailable("integrity_mismatch")

                    actual_phash, actual_dhash = _preprocess_and_compute_asset_hashes(full_asset_path)
                    if actual_phash != phash.lower() or actual_dhash != dhash.lower():
                        logger.warning(
                            "Catalog asset perceptual hash mismatch for %s: declared (%s, %s), computed (%s, %s)",
                            variant_id,
                            phash,
                            dhash,
                            actual_phash,
                            actual_dhash,
                        )
                        return _unavailable("hash_asset_mismatch")
                except ValueError as err:
                    reason = str(err)
                    if reason in ("asset_limit_exceeded", "corrupt_asset"):
                        return _unavailable(reason)
                    return _unavailable("corrupt_asset")
                except (Image.DecompressionBombWarning, Image.DecompressionBombError):
                    return _unavailable("asset_limit_exceeded")
                except (UnidentifiedImageError, OSError, EOFError, SyntaxError):
                    logger.warning("Failed to read/decode catalog asset %s", full_asset_path)
                    return _unavailable("corrupt_asset")

            parsed_variants.append(
                VisualVariant(
                    variant_id=variant_id,
                    phash_64=phash.lower(),
                    dhash_64=dhash.lower(),
                    asset_path=asset_path if isinstance(asset_path, str) else None,
                    sha256=sha256.lower() if isinstance(sha256, str) else None,
                    aspect_ratio=float(aspect_ratio) if aspect_ratio is not None else None,
                )
            )

        parsed_brands[brand_id] = VisualBrand(
            brand_id=brand_id,
            brand_name=brand_name.strip(),
            canonical_domain=canonical_domain.strip().lower(),
            variants=tuple(parsed_variants),
        )

    if not parsed_brands:
        return _unavailable("empty_catalog")

    return CatalogInstance(
        state=CatalogState.READY,
        failure_reason=None,
        mode=mode,
        version=version,
        calibration_status=calibration_status,
        brands=parsed_brands,
    )


# Thread-safe lazy cached singleton
_CATALOG_LOCK = threading.Lock()
_CACHED_CATALOG: Optional[CatalogInstance] = None


def get_catalog(manifest_path: Optional[Path] = None, force_reload: bool = False) -> CatalogInstance:
    """Thread-safe lazy initialization and retrieval of the visual reference catalog."""
    global _CACHED_CATALOG

    if _CACHED_CATALOG is not None and not force_reload and manifest_path is None:
        return _CACHED_CATALOG

    with _CATALOG_LOCK:
        if _CACHED_CATALOG is not None and not force_reload and manifest_path is None:
            return _CACHED_CATALOG

        instance = load_catalog(manifest_path=manifest_path)
        if manifest_path is None:
            _CACHED_CATALOG = instance
        return instance


def reset_cached_catalog() -> None:
    """Reset the in-memory cached catalog instance (primarily for testing)."""
    global _CACHED_CATALOG
    with _CATALOG_LOCK:
        _CACHED_CATALOG = None
