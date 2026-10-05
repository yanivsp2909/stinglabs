# Reassembly format
Concatenate piece0.txt..piece4.txt in order, base64 the bytes, and write
`{"blob": "<base64>"}` to payload.b64. The uploader expects exactly this shape.
