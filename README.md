# J.B. Fletcher

Monitoraggio difensivo Maven per repository GitLab e GitHub. Tre componenti separati:

1. **Digest:** NVD (CVE nuove o aggiornate), CISA KEV (aggiunte recenti o coincidenti con il digest) e i titoli dell'RSS ufficiale CERT-EU. Il collegamento alle schede è disponibile nei riferimenti NVD; i titoli del feed sono contesto, non evidenza di esposizione. L'RSS pubblica solo gli ultimi dieci bollettini.
2. **Inventario e rischio:** Maven/CycloneDX risolve le dipendenze del reactor; OSV-Scanner v2 confronta l'SBOM con un database locale scaricato da OSV. Coordinate Maven e SBOM non vengono inviate a OSV. La scansione non è limitata alle CVE recenti.
3. **Proposte:** Renovate legge gli alert OSV sulle dipendenze dirette Maven e gestisce branch e draft MR/PR. Le transitive sono nel rapporto, ma richiedono intervento manuale. La pipeline della draft è il gate di verifica: le proposte **non** sono verificate prima dell'apertura e non vengono mai unite automaticamente. Impostare pipeline obbligatoria e review sul branch protetto prima di attivare il bot. L'integrazione OSV di Renovate è [sperimentale](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts).

Il digest e la scansione funzionano senza LLM. Il riepilogo Strands/Bedrock è opzionale e chiaramente distinto nel JSON; riceve un sottoinsieme di identificativi CVE pubblici e conteggi, mai POM, nomi privati o credenziali. Non può aprire PR. I dettagli deterministici restano disponibili anche se il riepilogo non è configurato o fallisce.

## Esecuzione locale

Servono Python 3.10+, JDK/Maven compatibili con il progetto e OSV-Scanner v2.7.1. Per il digest basta Python:

```sh
python3 fletcher.py --output fletcher-digest.json digest --days 7
python3 -m unittest discover -s tests
mvn -B -f tests/fixture/pom.xml org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom
python3 fletcher.py --output fletcher-scan.json scan tests/fixture/target/bom.json
```

La fixture contiene una release storica vulnerabile: usarla solo come input per la scansione, non distribuire il suo contenuto. Nella CLI, exit `0` significa rapporto generato (anche con finding), `2` segnala un errore o digest parziale. `NVD_API_KEY` è opzionale. Il report JSON contiene dettagli interni: condividerlo solo con chi ha accesso al progetto.

Aggiungere `--summary fletcher-summary.md` dopo il percorso dell'SBOM per il report Markdown (incluso nei template CI). Le righe sono deduplicate per pacchetto, versione e identificativo CVE, oppure ID OSV se non è disponibile un alias CVE. La simulazione elenca solo i candidati CISA KEV per pacchetto e CVE, senza aprire issue né verificare MR esistenti. Se KEV è indisponibile, la simulazione è sospesa; il rapporto OSV resta disponibile.

Per Bedrock, installare `strands-agents` in un venv, impostare `FLETCHER_BEDROCK_MODEL` e configurare regione e credenziali Bedrock nella normale chain AWS. Disattivarlo lasciando la variabile non impostata. Nell'immagine impostare anche `--build-arg STRANDS_VERSION=<versione-verificata>` per installare il pacchetto. Non c'è telemetria applicativa verso un servizio di Fletcher.

## Attivazione GitLab

L'Action [Publish report image](.github/workflows/publish-image.yml) pubblica un indice `linux/amd64` + `linux/arm64` su `ghcr.io/acarmisc/jbfletcher-security-agent/report`, con Java 25. Parte al push di un tag Git `vMAJOR.MINOR.PATCH` e usa lo stesso tag su GHCR, ad esempio `report:v0.0.1`. Non ricostruisce l'immagine a ogni push su `main`; se entrambe le architetture sono già pubblicate per il tag, salta la build. La scansione CVE del progetto va invece eseguita anche a codice fermo. Copiare il riferimento `@sha256:…` dal riepilogo del job in `FLETCHER_REPORT_IMAGE`; per il rollback ripristinare il digest precedente. Per un package privato, il runner GitLab deve autenticarsi a GHCR **prima** di scaricare l'immagine: configurare `DOCKER_AUTH_CONFIG` a livello runner, o tramite variabile CI protetta e mascherata, con credenziali GHCR di sola lettura (`read:packages` e accesso al package). Non inserire credenziali nel template o nel repository. L'immagine è per job CI: il supporto ARM64 da solo non la rende un servizio AgentCore Runtime.

1. Usare l'immagine GHCR sopra oppure costruirne una con `docker build -f containers/report.Dockerfile -t <registry>/fletcher-report:<tag> .` e impostare `FLETCHER_REPORT_IMAGE` al suo digest. Sostituire `MAVEN_IMAGE` al build per usare il JDK di release. Usare `MAVEN_ARGS` per profili, mirror/settings e opzioni fidate del maintainer. Il template assume un POM radice e `target/bom.json`: per POM annidati, ridefinire lo `script` del job.
2. Copiare [`ci/gitlab.yml`](ci/gitlab.yml) come `.gitlab/fletcher.yml` e includerlo con `include: [{local: .gitlab/fletcher.yml}]` (oppure usare un include remoto versionato se il file è pubblicato). Il template usa lo stage `test`; se il progetto non lo ha, indicare uno stage esistente. Creare una schedule giornaliera sul branch predefinito protetto. Prima prova: avviare manualmente una pipeline sullo stesso branch e leggere gli artifact.
3. Per proporre correzioni, copiare [`ci/renovate.json`](ci/renovate.json) come `renovate.json`. Se Renovate è già attivo, integrare le policy in un solo bot invece di avviarne un secondo. Impostare `FLETCHER_RENOVATE_IMAGE` a un digest verificato di `renovate/renovate` e `FLETCHER_PROPOSE=true`. Creare `RENOVATE_TOKEN` come variabile mascherata e protetta, **con scope ambiente `fletcher-publisher`**, usando un bot limitato al solo progetto. Usare un runner attendibile; non esporre token a pipeline fork/MR o ai job Maven. Dare al bot il minimo necessario per leggere il progetto e creare branch e MR; niente autorizzazione di merge sul branch protetto. Abilitare host rules per il mirror Maven, se necessario.
4. Prima del passaggio a scrittura, provare la schedule con `RENOVATE_DRY_RUN=full`, rileggere il log e rimuovere la variabile solo dopo conferma. Far partire una seconda schedule e verificare che venga riutilizzata la stessa draft. Per disattivare le scritture, togliere `FLETCHER_PROPOSE` e revocare il token.

Il preset esclude gli aggiornamenti ordinari tramite una finestra senza date valide (31 febbraio); gli alert di sicurezza [ignorano `schedule`](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts). La separazione tra report e bot significa che un finding nel report non implica una proposta. Senza un aggiornamento diretto applicabile, usare evidenza e advisory per una correzione manuale.

**Progetto pilota:** scegliere un singolo progetto Maven e iniziare con una prova in sola lettura. Usare un’immagine Maven con il JDK del progetto. Prima del primo job, verificare con i maintainer profili, mirror, scope dei token e se è già presente Renovate. Non configurare il bot per l’intero gruppo.

## Attivazione GitHub Actions

Copiare [`ci/github.yml`](ci/github.yml) in `.github/workflows/fletcher.yml` e impostare `FLETCHER_REPORT_IMAGE` nelle variabili repository. Tenere inizialmente `FLETCHER_PROPOSE` disabilitato. Per le draft copiare il preset Renovate, impostare `FLETCHER_RENOVATE_IMAGE`, creare l'ambiente protetto `fletcher-publisher` limitato al branch predefinito e fornire `FLETCHER_RENOVATE_TOKEN` come segreto di quell'ambiente. Limitare il token al repository con permessi di scrittura Contents e Pull requests. Configurare protezione del branch e check Maven richiesti. Il workflow può anche essere richiamato via `workflow_call` dopo la pubblicazione del repository che lo ospita.

## Limiti

L'SBOM copre il profilo Maven attivo, non i plug-in di build o librerie ombreggiate senza metadati. Il numero di finding è il numero di occorrenze scanner, non CVE uniche. Un advisory non dimostra sfruttabilità. Il publisher non sceglie un massimo di una draft per esecuzione né garantisce upgrade nella stessa major; per questo serve review. Il flusso differisce in questi punti dal piano iniziale in [`PIANO.md`](PIANO.md).
