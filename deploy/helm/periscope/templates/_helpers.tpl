{{- define "periscope.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "periscope.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "periscope.selectorLabels" -}}
app.kubernetes.io/name: {{ include "periscope.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "periscope.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "periscope.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "periscope.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "periscope.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "periscope.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* "true" when an external database is configured (then nothing is stored on the volume) */}}
{{- define "periscope.externalDatabase" -}}
{{- if or .Values.database.url .Values.database.existingSecret -}}true{{- end -}}
{{- end -}}

{{/* "true" when the SQLite volume must be a PersistentVolumeClaim */}}
{{- define "periscope.persist" -}}
{{- if and .Values.persistence.enabled (not (include "periscope.externalDatabase" .)) -}}true{{- end -}}
{{- end -}}

{{/* Browser origins: explicit config.origins, else derived from the Ingress hosts (https when it has TLS). */}}
{{- define "periscope.origins" -}}
{{- if .Values.config.origins -}}
{{- toJson .Values.config.origins -}}
{{- else if and .Values.ingress.enabled .Values.ingress.hosts -}}
{{- $scheme := ternary "https" "http" (not (empty .Values.ingress.tls)) -}}
{{- $origins := list -}}
{{- range .Values.ingress.hosts -}}
{{- $origins = append $origins (printf "%s://%s" $scheme .host) -}}
{{- end -}}
{{- toJson $origins -}}
{{- else -}}
[]
{{- end -}}
{{- end -}}

{{/* WebAuthn RP ID: explicit config.rpId, else the first Ingress host. */}}
{{- define "periscope.rpId" -}}
{{- if .Values.config.rpId -}}
{{- .Values.config.rpId -}}
{{- else if and .Values.ingress.enabled .Values.ingress.hosts -}}
{{- (index .Values.ingress.hosts 0).host -}}
{{- end -}}
{{- end -}}

{{/* Fail early, with a readable message, on combinations that cannot work. */}}
{{- define "periscope.validate" -}}
{{- if not (or .Values.secretKey.existingSecret .Values.secretKey.value) -}}
{{- fail "secretKey: set secretKey.existingSecret (recommended) or secretKey.value. The key encrypts the stored BunkerWeb credentials; generate one with: openssl rand -base64 32 | tr '+/' '-_'" -}}
{{- end -}}
{{- if and (not .Values.persistence.enabled) (not (include "periscope.externalDatabase" .)) -}}
{{- fail "persistence: persistence.enabled=false needs an external database (database.url or database.existingSecret); SQLite on a volume would lose all data at every restart" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.hosts) -}}
{{- fail "ingress.hosts: at least one host is required when ingress.enabled is true, e.g. [{host: periscope.example.com}]" -}}
{{- end -}}
{{- if .Values.agentListener.enabled -}}
{{- if not (regexMatch "^https://[^/:[:space:]]+(:[0-9]{1,5})?/?$" .Values.agentListener.publicUrl) -}}
{{- fail "agentListener.publicUrl: required when agentListener.enabled is true, as https://host[:port] (the name or address agents use to reach the listener; it goes in the listener's certificate)" -}}
{{- end -}}
{{- end -}}
{{- if .Values.config.cookieSecure -}}
{{- if eq (include "periscope.origins" . | fromJsonArray | len) 0 -}}
{{- fail "config.origins: required when config.cookieSecure is true (the public URL, e.g. [\"https://periscope.example.com\"]); set config.cookieSecure=false for a plain-HTTP trial" -}}
{{- end -}}
{{- if not (include "periscope.rpId" .) -}}
{{- fail "config.rpId: required when config.cookieSecure is true (the domain name of the console)" -}}
{{- end -}}
{{- end -}}
{{- end -}}
