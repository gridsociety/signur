"""Compose the GitHub preview card, measuring the ink instead of guessing at it."""

import subprocess
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont

FONDO = (0x38, 0x38, 0x38)  # il disco del marchio, così il cerchio non si stacca
LARGHEZZA, ALTEZZA = 1280, 640
TITOLO, DIDASCALIA = "Signur", "Firma remota, sulla tua macchina"
SPAZIO = 64          # fra marchio e testi
INTERLINEA = 26      # fra la base del titolo e la cima della didascalia
SORGENTE = Path("assets/signur.svg")
DESTINAZIONE = Path("assets/social-preview.png")
TEMP = Path("/tmp/signur-marchio.png")


def marchio(lato: int) -> Image.Image:
    subprocess.run(
        ["rsvg-convert", "-w", str(lato), "-h", str(lato), str(SORGENTE), "-o", str(TEMP)],
        check=True,
    )
    with Image.open(TEMP) as reso:
        immagine = reso.convert("RGBA")
    # Il disco ha il colore della scheda, quindi non si vede: ciò che conta per
    # l'impaginazione è l'inchiostro, cioè la chiave e i baffi.
    piatto = Image.new("RGB", immagine.size, FONDO)
    piatto.paste(immagine, (0, 0), immagine)
    differenza = ImageChops.difference(piatto, Image.new("RGB", immagine.size, FONDO))
    maschera = differenza.convert("L").point(lambda v: 255 if v > 6 else 0)
    return immagine.crop(maschera.getbbox())


def riga(testo: str, font: ImageFont.FreeTypeFont, colore: tuple[int, int, int]) -> Image.Image:
    """Draw one line and hand back just its ink, so lines can be aligned exactly."""
    misura = Image.new("RGBA", (2000, 400), (0, 0, 0, 0))
    ImageDraw.Draw(misura).text((40, 40), testo, font=font, fill=(*colore, 255))
    return misura.crop(misura.getchannel("A").getbbox())


def componi() -> None:
    tela = Image.new("RGB", (LARGHEZZA, ALTEZZA), FONDO)
    titolo_font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Georgia Bold.ttf", 116)
    sotto_font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Georgia.ttf", 38)

    segno = marchio(300)
    titolo = riga(TITOLO, titolo_font, (245, 245, 243))
    didascalia = riga(DIDASCALIA, sotto_font, (178, 182, 176))

    larghezza_testi = max(titolo.width, didascalia.width)
    altezza_testi = titolo.height + INTERLINEA + didascalia.height
    sinistra = round((LARGHEZZA - (segno.width + SPAZIO + larghezza_testi)) / 2)
    centro = ALTEZZA / 2

    tela.paste(segno, (sinistra, round(centro - segno.height / 2)), segno)
    x = sinistra + segno.width + SPAZIO
    y = round(centro - altezza_testi / 2)
    tela.paste(titolo, (x, y), titolo)
    tela.paste(didascalia, (x, y + titolo.height + INTERLINEA), didascalia)
    tela.save(DESTINAZIONE, optimize=True)


if __name__ == "__main__":
    componi()
