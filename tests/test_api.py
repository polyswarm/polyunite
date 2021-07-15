import os

import pytest

import polyunite
from polyunite.apiconvert import convert_api_md_obj_to_engine_results_dict, convert_api_hs_obj_to_engine_results_dict
from polyswarm_api.api import PolyswarmAPI


@pytest.mark.parametrize(
    'q, family_expected', [
        ('triage_sandbox_v0.targets.family:*emotet* AND scan.detections.total:>4', 'emotet'),
    ]
)
def test_name_similarity_metric(q, family_expected):
    api = PolyswarmAPI(os.getenv("POLYSWARM_API_KEY"))
    mdo = next(api.search_by_metadata(q))
    mdo_for_unite = convert_api_md_obj_to_engine_results_dict(mdo)
    analysis = polyunite.analyze(mdo_for_unite)  # .name_similarity_metric(name)
    name = analysis.infer_name()

    assert "emotet" in name.lower()

    hdo = next(api.search(mdo.sha256))

    hdo_for_unite = convert_api_hs_obj_to_engine_results_dict(hdo)
    analysis = polyunite.analyze(hdo_for_unite)

    name = analysis.infer_name()

    assert "emotet" in name.lower()
