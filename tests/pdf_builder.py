"""Build small PDFs byte by byte, so a test can say exactly what is inside."""


def raw_pdf(objects: list[bytes], root_number: int = 1, hybrid: bool = False) -> bytes:
    """Assemble numbered objects into a PDF with a correct cross reference table.

    With ``hybrid`` the file also carries a cross reference *stream* announced by
    /XRefStm, the compatibility trick PDF 1.5 writers use and that many real
    documents in circulation contain.
    """
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_stream_offset = None
    if hybrid:
        count = len(objects) + 2  # the objects, the free entry and the stream itself
        rows = bytearray(b"\x00\x00\x00\xff")  # entry 0: free
        for offset in offsets[1:]:
            rows += b"\x01" + offset.to_bytes(2, "big") + b"\x00"
        stream_number = len(objects) + 1
        xref_stream_offset = len(out)
        rows += b"\x01" + xref_stream_offset.to_bytes(2, "big") + b"\x00"
        dictionary = (
            f"/Type /XRef /Size {count} /W [1 2 1] /Index [0 {count}]"
            f" /Root {root_number} 0 R"
        )
        out += f"{stream_number} 0 obj\n".encode()
        out += stream_object(dictionary, bytes(rows))
        out += b"\nendobj\n"

    start_xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode()
    size = len(objects) + (2 if xref_stream_offset is not None else 1)
    trailer = f"/Size {size} /Root {root_number} 0 R"
    if xref_stream_offset is not None:
        trailer += f" /XRefStm {xref_stream_offset}"
    out += (f"trailer\n<< {trailer} >>\nstartxref\n{start_xref}\n%%EOF\n").encode()
    return bytes(out)


def pdfa_xmp(part: str = "2", conformance: str = "B", attribute_form: bool = False) -> bytes:
    """An XMP packet declaring PDF/A, in either the element or the attribute form."""
    if attribute_form:
        description = (
            f'<rdf:Description rdf:about="" pdfaid:part="{part}" '
            f'pdfaid:conformance="{conformance}"/>'
        )
    else:
        description = (
            '<rdf:Description rdf:about="">'
            f"<pdfaid:part>{part}</pdfaid:part>"
            f"<pdfaid:conformance>{conformance}</pdfaid:conformance>"
            "</rdf:Description>"
        )
    return (
        '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
        'xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">'
        f"{description}</rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>"
    ).encode()


def stream_object(dictionary: str, data: bytes) -> bytes:
    return (
        f"<< {dictionary} /Length {len(data)} >>\nstream\n".encode() + data + b"\nendstream"
    )
