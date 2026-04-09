import axios from 'axios'

export const http = axios.create({
  timeout: 20000,           // increase to 20s
  validateStatus: () => true,
  maxRedirects: 3,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  },
})