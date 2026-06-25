import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

export const getStatus = () => api.get('/status').then(r => r.data)
export const getStats = () => api.get('/dashboard/stats').then(r => r.data)
export const getThreats = (params = {}) => api.get('/threats', { params }).then(r => r.data)
export const getThreatDetail = (id) => api.get(`/threats/${id}`).then(r => r.data)
export const getAlerts = (resolved = false) => api.get('/alerts', { params: { resolved } }).then(r => r.data)
export const resolveAlert = (id) => api.post(`/alerts/${id}/resolve`).then(r => r.data)
export const markFalsePositive = (id) => api.post(`/threats/${id}/false-positive`).then(r => r.data)
export const getLiveFeed = () => api.get('/threats/live/feed').then(r => r.data)
export const analyzeEmail = (data) => api.post('/analyze', data).then(r => r.data)
export const getAttentionState = () => api.get('/dashboard/attention').then(r => r.data)
export const markHandled = (id) => api.post(`/threats/${id}/handled`).then(r => r.data)
export default api