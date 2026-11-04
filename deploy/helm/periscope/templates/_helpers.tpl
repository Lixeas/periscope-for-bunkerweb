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

{{- define "periscope.origins" -}}
{{- toJson .Values.config.origins -}}
{{- end -}}

{{- define "periscope.rpId" -}}
{{- .Values.config.rpId -}}
{{- end -}}

{{/* Fail early, with a readable message, on combinations that cannot work. */}}
{{- define "periscope.validate" -}}
{{- if not (or .Values.secretKey.existingSecret .Values.secretKey.value) -}}
{{- fail "secretKey: set secretKey.existingSecret (recommended) or secretKey.value. The key encrypts the stored BunkerWeb credentials; generate one with: openssl rand -base64 32 | tr '+/' '-_'" -}}
{{- end -}}
{{- if and (not .Values.persistence.enabled) (not (include "periscope.externalDatabase" .)) -}}
{{- fail "persistence: persistence.enabled=false needs an external database (database.url or database.existingSecret); SQLite on a volume would lose all data at every restart" -}}
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
