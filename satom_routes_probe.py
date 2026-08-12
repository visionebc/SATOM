import re
from app import create_app
a = create_app()
pat = re.compile(r"sync|scan|refresh|discover|schema|catalog|probe|detect|version|firmware|upgrade|update|registry|explorer", re.I)
for r in sorted(a.url_map.iter_rules(), key=lambda x: str(x)):
    s = str(r)
    if pat.search(s) or pat.search(r.endpoint):
        m = sorted(r.methods - {"HEAD", "OPTIONS"})
        print("%-62s %-18s %s" % (s, ",".join(m), r.endpoint))
