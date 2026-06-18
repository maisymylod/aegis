from aegis.net import MtlsMaterial, mutual_handshake


def test_certified_client_accepted():
    result = mutual_handshake(MtlsMaterial.generate(), present_client_cert=True)
    assert result.ok is True
    assert result.peer_common_name == "gs-canberra"


def test_uncertified_client_rejected():
    result = mutual_handshake(MtlsMaterial.generate(), present_client_cert=False)
    assert result.ok is False
    assert result.error
