# GitLab: report, triage e issue

I tre job in `gitlab.yml` usano **lo stesso digest** in `FLETCHER_REPORT_IMAGE`. Non servono Kubernetes, kubeconfig o accesso al registry applicativo. Fletcher analizza le dipendenze Maven; per il sorgente Java mantenere un job SonarQube separato. Per partire, impostare `FLETCHER_PILOT=true` nella schedule sul branch predefinito protetto. Lasciare `FLETCHER_ISSUES` non impostata fino al collaudo del report. Il template usa lo stage `test`, ridefinibile su `.fletcher`.

Per isolare la schedule dalla CI ordinaria, spostare la configurazione esistente invariata in `.gitlab/normal.yml` e salvare il template Fletcher in `.gitlab/fletcher.yml`. Usare questo wrapper come `.gitlab-ci.yml`:

```yaml
include:
  - local: /.gitlab/normal.yml
    rules:
      - if: '$CI_PIPELINE_SOURCE != "schedule" || $FLETCHER_PILOT != "true"'
  - local: /.gitlab/fletcher.yml
    rules:
      - if: '$CI_PIPELINE_SOURCE == "schedule" && $FLETCHER_PILOT == "true"'
```

Nel file Fletcher dichiarare `stages: [test]` oppure usare lo stage predefinito GitLab. Impostare `MAVEN_ARGS` se servono profili o settings Maven (per esempio `-s ci_settings.xml`). Dopo il primo run verificare nella pipeline che ci siano solo report e triage e che entrambi abbiano caricato gli artifact. Se il progetto preferisce un include remoto, fissarlo a uno SHA verificato e mantenere le stesse regole di isolamento.

1. **`fletcher-report`** — bundle della scansione: `fletcher-scan.json` come evidenza per il job successivo, `fletcher-summary.md` da leggere e `fletcher-digest.json` come contesto generale. Un report incompleto non abilita i job successivi.
2. **`fletcher-triage`** — `fletcher-triage.json`, con finding ordinati, chiavi stabili e motivazioni verificabili. Per aggiungere evidenza runtime configurare `FLETCHER_RUNTIME_SCAN` come variabile CI di tipo File (output `scan` da uno SBOM della release distribuita) e `FLETCHER_RUNTIME_RELEASE` con la sua identità immutabile. Al momento è l'operatore che attesta la provenienza: nessuna scoperta automatica di servizi o artefatti. Solo una corrispondenza esatta di pacchetto, versione e advisory è un match; mancata corrispondenza significa `unverified`, non assenza di impatto.
3. **`fletcher-issue`** — azione manuale, nascosta per default. Per attivarla impostare `FLETCHER_ISSUES=true`, riservare ambiente `fletcher-issues` ai maintainer autorizzati e limitare a loro anche i permessi per le variabili di pipeline. Creare `FLETCHER_ISSUE_TOKEN` come variabile protetta e mascherata, con scope esatto `fletcher-issues`, per un bot del solo progetto con API access e permesso di gestire issue. Non usare segreti come variabili manuali. Aprire il job manuale dalla lista dei job e passare `FLETCHER_FINDING_KEY` copiando **una** chiave dal triage. Verificare prima esposizione, applicabilità e MR già esistenti: non c'è correlazione automatica con Renovate. Il job apre una issue confidenziale o restituisce una issue esistente, anche se chiusa, senza modificarla. I job di pubblicazione sono serializzati per progetto; l'artifact deve appartenere alla pipeline corrente.

`urgent-review` significa corrispondenza runtime e presenza in CISA KEV; `priority-review` indica uno dei due segnali. `review` significa che questi segnali non sono stati confermati, **non** che il rischio è basso. Non viene stimata la raggiungibilità del codice né l'esposizione di rete. Se il feed KEV è indisponibile, il triage mantiene le evidenze disponibili e blocca la pubblicazione. Nessuna apertura automatica, nessun LLM nella decisione.

Per le proposte correttive automatiche, includere separatamente `gitlab-renovate.yml`: non è uno dei tre job di triage e usa la sua immagine e identità dedicate.

## SBOM dell'immagine

Includere `runtime-sbom.yml` nella pipeline di build e aggiungere un job dopo il push. Il job di push deve pubblicare un artifact `reports:dotenv` con `IMAGE_REF=registry/repo@sha256:…` (digest del manifest della piattaforma distribuita, non tag o indice multi-arch). Il runner Syft serve accesso di sola lettura al registry; il login kubelet per l'immagine del job non autentica automaticamente Syft.

```yaml
runtime-sbom:
  extends: .fletcher-runtime-sbom
  stage: inventory # dichiarare dopo il push, prima del deploy
  needs:
    - job: docker-build-push
      artifacts: true
```

Distribuire lo stesso digest e conservare `runtime/bom.json` e `runtime/image.ref` in uno storage privato per tutta la vita della release. Per la prova, scaricare i due file dalla build effettivamente distribuita:

```sh
python3 fletcher.py --output runtime-scan.json scan runtime/bom.json
python3 fletcher.py --output fletcher-triage.json triage fletcher-scan.json \
  --runtime-scan runtime-scan.json --runtime-release "$(cat runtime/image.ref)"
```

SonarQube resta il controllo del sorgente. Lo SBOM di Syft documenta il contenuto dell'immagine e non attesta raggiungibilità o sfruttabilità delle dipendenze.
