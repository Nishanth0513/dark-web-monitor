from io import BytesIO
from datetime import datetime
from typing import List

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from models import Breach, User


def generate_breach_report(user: User, breaches: List[Breach], risk_level: str) -> BytesIO:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    _, height = letter

    y = height - 50
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "Dark Web Breach Report")

    y -= 30
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"User: {user.email}")

    y -= 20
    c.drawString(50, y, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    y -= 20
    c.drawString(50, y, f"Overall Risk Level: {risk_level}")

    y -= 30
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Breaches:")

    c.setFont("Helvetica", 11)
    y -= 20

    if not breaches:
        c.drawString(50, y, "No breaches detected for your monitored emails.")
        y -= 20
    else:
        for b in breaches:
            if y < 80:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 11)

            c.drawString(
                50,
                y,
                f"{b.breach_date.strftime('%Y-%m-%d')} - {b.breach_name} ({b.severity}) on {b.email}",
            )
            y -= 15
            c.drawString(60, y, f"Data exposed: {b.data_exposed}")
            y -= 25

    if y < 120:
        c.showPage()
        y = height - 60

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Recommendations:")

    c.setFont("Helvetica", 11)
    y -= 20
    recommendations = [
        "Use strong, unique passwords for every account.",
        "Enable multi-factor authentication wherever possible.",
        "Monitor your financial and bank statements regularly.",
        "Avoid reusing passwords across different websites.",
        "Consider using a password manager.",
    ]
    for rec in recommendations:
        if y < 60:
            c.showPage()
            y = height - 60
            c.setFont("Helvetica", 11)
        c.drawString(50, y, f"- {rec}")
        y -= 15

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer

