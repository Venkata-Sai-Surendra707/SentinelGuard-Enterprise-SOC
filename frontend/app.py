import os
import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title='SentinelGuard SOC',page_icon='🛡️',layout='wide')
st.title('🛡️ SentinelGuard | Security Operations Center')
st.caption('Synthetic telemetry only · Evidence-first detection · Analyst-controlled triage')
api=st.sidebar.text_input('API URL',value=os.getenv('API_URL','http://localhost:8000'))
key=st.sidebar.text_input('API key',value=os.getenv('SENTINELGUARD_API_KEY',''),type='password')

def request(method,path,**kwargs):
    try:
        r=requests.request(method,api.rstrip('/')+path,headers={'X-API-Key':key},timeout=25,**kwargs)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        st.error(f'API request failed: {e}')
        return None

if not key:
    st.warning('Enter the API key in the sidebar. The API requires authentication.')
    st.stop()

c1,c2,c3=st.columns(3)
with c1:
    if st.button('Generate synthetic telemetry',use_container_width=True):
        result=request('POST','/simulate?count=500&seed=42')
        if result: st.success(f"Inserted {result['inserted']} simulated events")
with c2:
    if st.button('Run detections',use_container_width=True):
        result=request('POST','/detect')
        if result: st.success(f"{result['new_incidents']} new incidents from {result['evaluated_events']} events")
with c3:
    if st.button('Refresh dashboard',use_container_width=True): st.rerun()

metrics=request('GET','/metrics')
if metrics:
    a,b,c=st.columns(3)
    a.metric('Security events',metrics['events'])
    b.metric('Total incidents',metrics['incidents'])
    c.metric('Active incidents',sum(v for k,v in metrics['by_status'].items() if k!='closed'))
    left,right=st.columns(2)
    with left:
        st.subheader('Severity breakdown')
        if metrics['by_severity']: st.bar_chart(pd.Series(metrics['by_severity']))
    with right:
        st.subheader('Detection rules')
        if metrics['by_rule']: st.bar_chart(pd.Series(metrics['by_rule']))

st.subheader('Incident queue')
incidents=request('GET','/incidents?limit=200')
if incidents is not None:
    if incidents:
        df=pd.DataFrame(incidents)
        st.dataframe(df[['id','severity','status','rule_id','entity','title','last_seen','assignee']],use_container_width=True,hide_index=True)
        selected=st.selectbox('Select incident',options=[i['id'] for i in incidents])
        row=next(i for i in incidents if i['id']==selected)
        with st.expander('Evidence and investigation',expanded=True):
            st.write('**Detection rationale:**',row['rationale'])
            st.write('**ATT&CK technique:**',row['technique'])
            st.write('**Evidence event IDs:**',', '.join(row['evidence']))
            explanation=request('GET',f'/incidents/{selected}/analysis')
            if explanation:
                st.info(explanation['confidence'])
                for action in explanation['recommended_actions']: st.write('•',action)
            with st.form('triage'):
                status=st.selectbox('Status',['open','investigating','contained','closed'],index=['open','investigating','contained','closed'].index(row['status']))
                assignee=st.text_input('Assignee',value=row['assignee'])
                note=st.text_area('Analyst note')
                if st.form_submit_button('Save investigation'):
                    result=request('PATCH',f'/incidents/{selected}',json={'status':status,'assignee':assignee,'note':note or None})
                    if result: st.success('Incident updated'); st.rerun()
    else: st.info('Generate simulated telemetry, then run detections.')
    if incidents:
        st.download_button('Export incident summary (CSV)',pd.DataFrame(incidents).to_csv(index=False).encode(),'sentinelguard-incidents.csv','text/csv')
