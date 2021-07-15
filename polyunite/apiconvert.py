from polyswarm_api.resources import Metadata, Hash, ArtifactInstance
from polyunite.errors import PolyuniteError


def convert_api_md_obj_to_engine_results_dict(md_object_from_api: Metadata):
    if md_object_from_api.total_detections < 1:
        # todo new error?
        raise PolyuniteError(
            "need engine assertions to operate, {} has zero assertions".format(md_object_from_api.sha256))

    dr = dict()
    ls = md_object_from_api.json.get("scan").get('latest_scan')

    for engine_r, engine_md in md_object_from_api.json.get("scan").get('latest_scan').items():
        if isinstance(engine_md, dict):
            mwf = engine_md.get("metadata", dict()).get("malware_family")
            if mwf:
                dr[engine_r] = mwf

    return dr


def convert_api_hs_obj_to_engine_results_dict(hs_object_from_api: ArtifactInstance):
    if not hs_object_from_api.assertions:
        # todo new error?
        raise PolyuniteError(
            "need engine assertions to operate, {} has zero assertions".format(hs_object_from_api.sha256))

    dr = dict()

    for assertion in hs_object_from_api.assertions:
        engine_r, mwf = assertion.engine_name, assertion.metadata.get("malware_family", "")
        dr[engine_r] = mwf

    return dr
