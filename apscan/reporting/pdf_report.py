from apscan.reporting.base import Reporter
from apscan.core.context import ScanContext
from xhtml2pdf import pisa
from io import BytesIO

class PDFReporter(Reporter):
    def generate(self, context: ScanContext):
        # reuse HTML content logic or duplicate if needed.
        # Ideally we reuse the logic from HTMLReporter.
        # But separate class design suggests we might want to just accept content.
        pass

    @staticmethod
    def convert_html_to_pdf(html_content: str) -> bytes:
        result = BytesIO()
        pdf = pisa.pisaDocument(BytesIO(html_content.encode("UTF-8")), result)
        if not pdf.err:
            return result.getvalue()
        return None
