from cc_utils import Ccutils
try:
    eid = Ccutils()
except:
    from Client import main
    main(None)
else:
    from Client import main
    main(eid)