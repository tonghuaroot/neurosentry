{{- define "neurosentry.name" -}}
neurosentry
{{- end -}}

{{- define "neurosentry.labels" -}}
app.kubernetes.io/name: neurosentry
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: neurosentry-{{ .Chart.Version }}
{{- end -}}

{{- define "neurosentry.selectorLabels" -}}
app.kubernetes.io/name: neurosentry
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "neurosentry.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
