def test_api_auth_and_pipeline(client):
    assert client.get('/metrics').status_code==401
    h={'X-API-Key':'test-secret'}
    s=client.post('/simulate?count=50&seed=10',headers=h)
    assert s.status_code==200 and s.json()['inserted']==62
    assert client.post('/simulate?count=50&seed=10',headers=h).json()['inserted']==0
    first=client.post('/detect',headers=h).json()
    assert first['new_incidents']>=5
    assert client.post('/detect',headers=h).json()['new_incidents']==0
    incidents=client.get('/incidents',headers=h).json()
    assert any(i['severity']=='critical' for i in incidents)
    incident_id=incidents[0]['id']
    assert client.patch(f'/incidents/{incident_id}',json={'status':'investigating','assignee':'analyst1','note':'triage started'},headers=h).json()['notes'][0]['text']=='triage started'
    explanation=client.get(f'/incidents/{incident_id}/analysis',headers=h).json()
    assert explanation['evidence_ids']
    assert explanation['confidence']=='rule-match, not confirmed compromise'
