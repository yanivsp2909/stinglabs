from sparta.tagging import IGNORE, LABEL2ID, Scorer, decode, token_labels

O, BS, IS, BN, IN = (LABEL2ID[k] for k in ("O", "B-SECRET", "I-SECRET", "B-NAME", "I-NAME"))


def test_token_labels_bio_and_specials():
    # text: "pw=abcdef by Dana Levi"
    spans = [{"start": 3, "end": 9, "label": "SECRET", "kind": "password"},
             {"start": 13, "end": 22, "label": "NAME", "kind": "name_he"},
             {"start": 0, "end": 2, "label": "DECOY", "kind": "placeholder"}]
    offsets = [(0, 0), (0, 2), (2, 3), (3, 6), (6, 9), (9, 12), (13, 17), (17, 22), (0, 0)]
    assert token_labels(offsets, spans) == [IGNORE, O, O, BS, IS, O, BN, IN, IGNORE]


def test_decode_roundtrip_and_orphan_i():
    offsets = [(0, 0), (0, 2), (3, 6), (6, 9), (13, 17), (17, 22)]
    assert decode(offsets, [IGNORE, O, BS, IS, BN, IN]) == [
        {"start": 3, "end": 9, "label": "SECRET"}, {"start": 13, "end": 22, "label": "NAME"}]
    assert decode(offsets, [IGNORE, O, IS, IS, O, IN]) == [
        {"start": 3, "end": 9, "label": "SECRET"}, {"start": 17, "end": 22, "label": "NAME"}]
    # adjacent B-B are two spans; type change splits
    assert len(decode(offsets, [IGNORE, O, BS, BS, BN, IS])) == 4


def test_scorer_counts():
    doc = {"spans": [{"start": 0, "end": 10, "label": "SECRET", "kind": "password"},
                     {"start": 20, "end": 30, "label": "NAME", "kind": "name_ar"},
                     {"start": 40, "end": 50, "label": "DECOY", "kind": "uuid"},
                     {"start": 60, "end": 70, "label": "DECOY", "kind": "git_sha"}]}
    pred = [{"start": 2, "end": 10, "label": "SECRET"},     # catches the secret (partial)
            {"start": 20, "end": 30, "label": "SECRET"},    # wrong type on the name
            {"start": 45, "end": 48, "label": "SECRET"},    # decoy false tag
            {"start": 80, "end": 85, "label": "NAME"}]      # tag on nothing
    s = Scorer()
    s.add(doc, pred)
    out = s.summary()
    assert out["SECRET"]["gold"] == 1 and out["SECRET"]["caught"] == 1
    assert out["SECRET"]["predicted"] == 3 and out["SECRET"]["precision"] == 1 / 3
    assert abs(out["SECRET"]["mean_char_iou"] - 0.8) < 1e-9
    assert out["NAME"]["recall"] == 0 and out["NAME"]["precision"] == 0
    assert out["DECOY"]["false_tagged"] == 1 and out["DECOY"]["false_tag_rate"] == 0.5
    assert out["by_kind"]["NAME/name_ar"]["caught"] == 0
    assert len(s.misses) == 1 and len(s.false_tags) == 3


def test_decode_trims_leading_space_from_bpe_offsets():
    text = "pw=abc by Dana Levi"
    offsets = [(0, 0), (0, 2), (2, 3), (3, 6), (6, 9), (9, 14), (14, 19)]
    assert decode(offsets, [IGNORE, O, O, BS, O, BN, IN], text) == [
        {"start": 3, "end": 6, "label": "SECRET"}, {"start": 10, "end": 19, "label": "NAME"}]


def test_ignore_spans_stay_out_of_labels_and_scores():
    # text: "mail ops@x.io now" ; the e-mail is IGNORE
    spans = [{"start": 5, "end": 13, "label": "IGNORE", "kind": "email"}]
    offsets = [(0, 0), (0, 4), (5, 8), (8, 9), (9, 13), (14, 17), (0, 0)]
    assert token_labels(offsets, spans) == [IGNORE, O, IGNORE, IGNORE, IGNORE, O, IGNORE]
    s = Scorer()
    s.add({"spans": spans}, [{"start": 5, "end": 13, "label": "SECRET"}])
    out = s.summary()
    assert out["SECRET"]["predicted"] == 0 and out["SECRET"]["gold"] == 0 and not s.false_tags


def test_a_tag_spilling_into_an_email_is_clipped_not_dropped():
    from sparta.tagging import Scorer
    text = "key=abcd1234efgh5678 mail ops@example.invalid now"
    s, e = text.index("abcd"), text.index(" mail")
    m = text.index("ops@")
    doc = {"text": text, "spans": [{"start": s, "end": e, "label": "SECRET", "kind": "k"},
                                   {"start": m, "end": m + len("ops@example.invalid"), "label": "IGNORE", "kind": "email"}]}
    sc = Scorer()
    sc.add(doc, [{"start": s, "end": m + 5, "label": "SECRET"}])          # the secret, then into the e-mail
    out = sc.summary()
    assert out["SECRET"]["caught"] == 1 and out["SECRET"]["predicted"] == 1
    sc = Scorer()
    sc.add(doc, [{"start": text.index("mail"), "end": m + 5, "label": "NAME"}])   # a false tag that runs into it
    assert sc.summary()["NAME"]["predicted"] == 1 and sc.false_tags
