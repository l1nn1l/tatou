def test_create_and_read_watermark(client, auth_headers, uploaded_doc_id):
    # Create watermark with AddAfterEOF method
    resp = client.post(f"/api/create-watermark/{uploaded_doc_id}", json={
        "method": "AddAfterEOF",
        "position": "top",
        "key": "unit-test-key",
        "secret": "hidden-msg",
        "intended_for": "bob@example.com"
    }, headers=auth_headers)

    assert resp.status_code == 200
    version_info = resp.get_json()

    # Read back watermark
    resp = client.post(f"/api/read-watermark/{uploaded_doc_id}", json={
        "method": version_info["method"],
        "position": version_info["position"],
        "key": "unit-test-key"
    }, headers=auth_headers)

    assert resp.status_code == 200
    assert resp.get_json()["secret"] == "hidden-msg"
