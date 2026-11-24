"""Diagram Studio's engine: the ``satom.diagram/1`` model, the importers, the
recogniser and the exporters. Standalone (stdlib + its own modules + the
optional CV/OCR wheels, imported lazily) so the runner can execute it inside
the bubblewrap jail -- see model.py."""
