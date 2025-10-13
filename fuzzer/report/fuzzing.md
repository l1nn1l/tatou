# Fuzzing — rapport

## Syfte
Testa Tatou upload-endpoint mot malformed PDF inputs genom mutation-based fuzzing (radamsa) för att hitta hanteringsfel (500).

## Metod
- Genererade 200 muterade PDF-filer med radamsa.
- Postade var och en till `/upload-document` med ett Python-harness (`http_fuzzer.py`).
- Sparade inputs som gav 5xx i `fuzz/crashes/` och skapade pytest-regressioner.

## Resultat
- Antal testade inputs: X
- Antal 5xx hittade: Y
- Exempel fil(er): `fuzz/crashes/mut_42.pdf` (se test `tests/test_regression_from_fuzz.py`).

## Förbättringar
- Använd white-box Atheris mot inre PDF-parser för fler buggar.
- Integrera i CI så regressioner inte återkommer.
