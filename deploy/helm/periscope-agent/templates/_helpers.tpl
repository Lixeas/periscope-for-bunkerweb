{{- define "periscope-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "periscope-agent.fullname" -}}
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

{{- define "periscope-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "periscope-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "periscope-agent.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "periscope-agent.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "periscope-agent.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "periscope-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "periscope-agent.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}


{{/* Fail early, with a readable message, on missing inputs. */}}
{{- define "periscope-agent.validate" -}}
{{- if not .Values.bunkerweb.url -}}
{{- fail "bunkerweb.url: required, the URL of the local BunkerWeb API with its root prefix, e.g. http://bunkerweb-api:8888" -}}
{{- end -}}
{{- if not (or .Values.enrollment.bundle .Values.enrollment.existingSecret) -}}
{{- fail "enrollment: set enrollment.bundle or enrollment.existingSecret (the bundle shown once by the console when you create the agent instance)" -}}
{{- end -}}
{{- if not (or .Values.bunkerweb.password .Values.bunkerweb.existingSecret) -}}
{{- fail "bunkerweb.password: set bunkerweb.password or bunkerweb.existingSecret (the password of the restricted BunkerWeb API user)" -}}
{{- end -}}
{{- end -}}
