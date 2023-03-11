import streamlit as st
from enumerator import full_enumerator

st.title("KitSec Domain Enumerator")

domain = st.text_input("Enter a domain name:")

if st.button("Enumerate"):
    results = full_enumerator(request=True, technology=True, active=False, domain=domain)
    st.write(results)
