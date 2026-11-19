# Renders the published specifications (spec/*.md) to HTML and PDF in dist/.
#
#   make            HTML and PDF
#   make html       HTML only (Python 3 + markdown-it-py)
#   make pdf        PDF with a cover page and page numbers, printed by a headless
#                   Chrome/Chromium; needs pdftotext (poppler-utils)
#   make vectors    check that the published vectors reproduce from their generators
#
# REV is recorded in each file's footer and used for links back to the repository;
# set it to a tag when cutting a release: make REV=v1.0.0

DIST   ?= dist
REV    ?= $(shell git describe --tags --always 2>/dev/null || echo main)
CHROME ?= $(shell for c in chromium chromium-browser google-chrome; do command -v $$c && break; done)
DOCS    = shieldnet-transport-v1 shieldnet-message-layer-v1 shieldled-device-protocol-v1
HTML    = $(DOCS:%=$(DIST)/%.html)
PDF     = $(DOCS:%=$(DIST)/%.pdf)

all: html pdf

html: $(HTML)

$(HTML) &: spec/transport.md spec/message-layer.md spec/application.md tools/build_spec.py
	python3 tools/build_spec.py $(DIST) --rev $(REV)

pdf: $(PDF)

$(PDF) &: spec/transport.md spec/message-layer.md spec/application.md tools/build_spec.py
	@test -n "$(CHROME)" || { echo "no Chrome/Chromium found; set CHROME=/path/to/browser"; exit 1; }
	python3 tools/build_spec.py $(DIST) --rev $(REV) --pdf $(CHROME)

vectors:
	python3 vectors/gen_vectors.py | cmp - vectors/shieldnet-v1-vectors.json
	python3 vectors/gen_msglayer_vectors.py | cmp - vectors/shieldnet-msglayer-vectors.json

clean:
	rm -rf $(DIST)

.PHONY: all html pdf vectors clean
