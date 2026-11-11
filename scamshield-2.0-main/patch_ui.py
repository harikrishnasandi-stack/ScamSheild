path = "app.py"
s = open(path, encoding="utf-8-sig").read()

fixes = [
    (
        'st.markdown(\'<div class="ss-panel">\', unsafe_allow_html=True)\n\n'
        '            st.markdown(\n'
        '                f"""\n'
        '                <div class="ss-verdict-label"',
        'st.markdown(\n'
        '                f"""\n'
        '                <div class="ss-panel">\n'
        '                <div class="ss-verdict-label"',
    ),
    (
        '                </div>\n'
        '                """,\n'
        '                unsafe_allow_html=True,\n'
        '            )\n'
        '            st.markdown("</div>", unsafe_allow_html=True)',
        '                </div>\n'
        '                </div>\n'
        '                """,\n'
        '                unsafe_allow_html=True,\n'
        '            )',
    ),
    (
        'background: linear-gradient(to right, #2F7D5B 0%, #2F7D5B 33%, #B8860B 33%, #B8860B 66%, #B23A2E 66%, #B23A2E 100%);\n'
        '        opacity: 0.35;',
        'background: linear-gradient(to right, rgba(47,125,91,0.35) 0%, rgba(47,125,91,0.35) 33%, '
        'rgba(184,134,11,0.35) 33%, rgba(184,134,11,0.35) 66%, rgba(178,58,46,0.35) 66%, rgba(178,58,46,0.35) 100%);',
    ),
]

for old, new in fixes:
    if s.count(old) != 1:
        print("Could not apply a fix (already applied or file differs). Nothing changed.")
        raise SystemExit(1)
for old, new in fixes:
    s = s.replace(old, new)

open(path, "w", encoding="utf-8").write(s)
print("app.py patched successfully.")
