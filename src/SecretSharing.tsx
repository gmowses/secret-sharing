import { useState, useCallback } from 'react'
import { Lock, Unlock, Copy, Check, Plus, Trash2, Sun, Moon, Languages, AlertTriangle, CheckCircle } from 'lucide-react'

// ── i18n ─────────────────────────────────────────────────────────────────────
const translations = {
  en: {
    title: "Shamir's Secret Sharing",
    subtitle: 'Split a secret into N shares. Any K of them reconstruct it. Pure math over GF(256) — client-side only.',
    splitTab: 'Split Secret',
    recoverTab: 'Recover Secret',
    secretLabel: 'Secret text',
    secretPlaceholder: 'Enter your secret...',
    totalShares: 'Total shares (N)',
    threshold: 'Threshold (K)',
    thresholdNote: 'Minimum shares needed to recover',
    split: 'Split',
    shares: 'Shares',
    sharesDesc: 'Distribute these shares',
    copyShare: 'Copy',
    copiedShare: 'Copied',
    copyAll: 'Copy All',
    copiedAll: 'Copied!',
    recoverLabel: 'Enter shares (one per line)',
    recoverPlaceholder: 'Paste K shares here, one per line...',
    recover: 'Recover',
    recovered: 'Recovered Secret',
    errorEmpty: 'Enter a secret to split.',
    errorKgtN: 'K (threshold) must be ≤ N (total shares).',
    errorKmin: 'K must be at least 2.',
    errorNmin: 'N must be at least 2.',
    errorNmax: 'N cannot exceed 255.',
    errorRecover: 'Could not recover secret. Check that shares are valid and you have at least K of them.',
    errorTooFew: 'Enter at least K shares.',
    errorBadFormat: 'Invalid share format. Each line should be: index:hexdata',
    howTitle: 'How it works',
    howText: 'Shamir\'s Secret Sharing splits each byte of the secret using a random polynomial of degree K-1 over GF(256). The secret is the polynomial evaluated at x=0. Any K points uniquely determine the polynomial via Lagrange interpolation.',
    builtBy: 'Built by',
    notice: 'This tool is for educational purposes. For production use, verify the implementation against a trusted library.',
    share: 'Share',
  },
  pt: {
    title: 'Compartilhamento de Segredo de Shamir',
    subtitle: 'Divida um segredo em N partes. Qualquer K delas o reconstroem. Matematica pura sobre GF(256) — so no navegador.',
    splitTab: 'Dividir Segredo',
    recoverTab: 'Recuperar Segredo',
    secretLabel: 'Texto secreto',
    secretPlaceholder: 'Digite seu segredo...',
    totalShares: 'Total de partes (N)',
    threshold: 'Limiar (K)',
    thresholdNote: 'Minimo de partes para recuperar',
    split: 'Dividir',
    shares: 'Partes',
    sharesDesc: 'Distribua estas partes',
    copyShare: 'Copiar',
    copiedShare: 'Copiado',
    copyAll: 'Copiar tudo',
    copiedAll: 'Copiado!',
    recoverLabel: 'Digite as partes (uma por linha)',
    recoverPlaceholder: 'Cole K partes aqui, uma por linha...',
    recover: 'Recuperar',
    recovered: 'Segredo Recuperado',
    errorEmpty: 'Digite um segredo para dividir.',
    errorKgtN: 'K (limiar) deve ser <= N (total de partes).',
    errorKmin: 'K deve ser pelo menos 2.',
    errorNmin: 'N deve ser pelo menos 2.',
    errorNmax: 'N nao pode ultrapassar 255.',
    errorRecover: 'Nao foi possivel recuperar o segredo. Verifique se as partes sao validas e se voce tem pelo menos K delas.',
    errorTooFew: 'Insira pelo menos K partes.',
    errorBadFormat: 'Formato de parte invalido. Cada linha deve ser: indice:hexdata',
    howTitle: 'Como funciona',
    howText: 'O Compartilhamento de Segredo de Shamir divide cada byte do segredo usando um polinomio aleatorio de grau K-1 sobre GF(256). O segredo e o polinomio avaliado em x=0. Qualquer K pontos determinam unicamente o polinomio via interpolacao de Lagrange.',
    builtBy: 'Criado por',
    notice: 'Esta ferramenta e para fins educacionais. Para uso em producao, verifique a implementacao com uma biblioteca confiavel.',
    share: 'Parte',
  },
} as const
type Lang = keyof typeof translations

// ── GF(256) arithmetic ─────────────────────────────────────────────────────
// GF(2^8) with primitive polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
const GF_EXP = new Uint8Array(512)
const GF_LOG = new Uint8Array(256)
;(function initGF() {
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11b
    x &= 0xff
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]
})()

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0
  return GF_EXP[GF_LOG[a] + GF_LOG[b]]
}
function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('division by zero in GF')
  if (a === 0) return 0
  return GF_EXP[(GF_LOG[a] - GF_LOG[b] + 255) % 255]
}
function gfPow(x: number, pow: number): number {
  return GF_EXP[(GF_LOG[x] * pow) % 255]
}

// Evaluate polynomial at x
function polyEval(coeffs: Uint8Array, x: number): number {
  let result = 0
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gfMul(result, x) ^ coeffs[i]
  }
  return result
}

// Lagrange interpolation at x=0
function lagrangeInterp(xs: number[], ys: number[]): number {
  let secret = 0
  for (let i = 0; i < xs.length; i++) {
    let num = ys[i]
    let den = 1
    for (let j = 0; j < xs.length; j++) {
      if (i !== j) {
        num = gfMul(num, xs[j])
        den = gfMul(den, xs[i] ^ xs[j])
      }
    }
    secret ^= gfDiv(num, den)
  }
  return secret
}

// Split one byte into N shares using K-1 degree polynomial
function splitByte(secret: number, n: number, k: number): Uint8Array {
  const coeffs = new Uint8Array(k)
  coeffs[0] = secret
  crypto.getRandomValues(coeffs.subarray(1))
  const shares = new Uint8Array(n)
  for (let x = 1; x <= n; x++) shares[x - 1] = polyEval(coeffs, x)
  return shares
}

// Split secret bytes, return array of hex strings "index:hex"
function splitSecret(secret: Uint8Array, n: number, k: number): string[] {
  const shareData: Uint8Array[] = Array.from({ length: n }, () => new Uint8Array(secret.length))
  for (let b = 0; b < secret.length; b++) {
    const s = splitByte(secret[b], n, k)
    for (let i = 0; i < n; i++) shareData[i][b] = s[i]
  }
  return shareData.map((d, i) =>
    `${i + 1}:${Array.from(d).map(v => v.toString(16).padStart(2, '0')).join('')}`
  )
}

// Recover from K share strings
function recoverSecret(shareStrings: string[]): Uint8Array {
  const parsed = shareStrings.map(s => {
    const [idx, hex] = s.trim().split(':')
    if (!idx || !hex || !/^[0-9a-fA-F]+$/.test(hex)) throw new Error('bad-format')
    const x = parseInt(idx)
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return { x, bytes }
  })
  const len = parsed[0].bytes.length
  const result = new Uint8Array(len)
  for (let b = 0; b < len; b++) {
    const xs = parsed.map(p => p.x)
    const ys = parsed.map(p => p.bytes[b])
    result[b] = lagrangeInterp(xs, ys)
  }
  return result
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function SecretSharing() {
  const [lang, setLang] = useState<Lang>(() => navigator.language.startsWith('pt') ? 'pt' : 'en')
  const [dark, setDark] = useState(() => {
    const d = window.matchMedia('(prefers-color-scheme: dark)').matches
    document.documentElement.classList.toggle('dark', d)
    return d
  })
  const [tab, setTab] = useState<'split' | 'recover'>('split')
  const [secret, setSecret] = useState('')
  const [n, setN] = useState(5)
  const [k, setK] = useState(3)
  const [shares, setShares] = useState<string[]>([])
  const [splitError, setSplitError] = useState('')
  const [recoverInput, setRecoverInput] = useState('')
  const [recovered, setRecovered] = useState('')
  const [recoverError, setRecoverError] = useState('')
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null)
  const [copiedAll, setCopiedAll] = useState(false)
  const [copiedRecovered, setCopiedRecovered] = useState(false)

  const t = translations[lang]
  const toggleDark = () => { const d=!dark; setDark(d); document.documentElement.classList.toggle('dark',d) }

  const handleSplit = useCallback(() => {
    setSplitError(''); setShares([])
    if (!secret) { setSplitError(t.errorEmpty); return }
    if (n < 2) { setSplitError(t.errorNmin); return }
    if (n > 255) { setSplitError(t.errorNmax); return }
    if (k < 2) { setSplitError(t.errorKmin); return }
    if (k > n) { setSplitError(t.errorKgtN); return }
    try {
      const bytes = new TextEncoder().encode(secret)
      setShares(splitSecret(bytes, n, k))
    } catch (e) {
      setSplitError(String(e))
    }
  }, [secret, n, k, t])

  const handleRecover = useCallback(() => {
    setRecoverError(''); setRecovered('')
    const lines = recoverInput.split('\n').map(l => l.trim()).filter(Boolean)
    if (lines.length < 2) { setRecoverError(t.errorTooFew); return }
    for (const l of lines) {
      if (!/^\d+:[0-9a-fA-F]+$/.test(l)) { setRecoverError(t.errorBadFormat); return }
    }
    try {
      const bytes = recoverSecret(lines)
      setRecovered(new TextDecoder().decode(bytes))
    } catch (e) {
      const msg = String(e)
      if (msg.includes('bad-format')) setRecoverError(t.errorBadFormat)
      else setRecoverError(t.errorRecover)
    }
  }, [recoverInput, t])

  const copyShare = (i: number) => {
    navigator.clipboard.writeText(shares[i]).then(() => { setCopiedIdx(i); setTimeout(() => setCopiedIdx(null), 1500) })
  }
  const copyAll = () => {
    navigator.clipboard.writeText(shares.join('\n')).then(() => { setCopiedAll(true); setTimeout(() => setCopiedAll(false), 2000) })
  }
  const copyRecovered = () => {
    navigator.clipboard.writeText(recovered).then(() => { setCopiedRecovered(true); setTimeout(() => setCopiedRecovered(false), 1500) })
  }

  // Use gfPow to silence "unused" warning — it's used internally
  void gfPow

  return (
    <div className="min-h-screen flex flex-col bg-white dark:bg-[#09090b] text-zinc-900 dark:text-zinc-100 transition-colors">
      <header className="border-b border-zinc-200 dark:border-zinc-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-red-500 rounded-lg flex items-center justify-center">
              <Lock size={18} className="text-white" />
            </div>
            <span className="font-semibold">Secret Sharing</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setLang(l => l === 'en' ? 'pt' : 'en')} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              <Languages size={14} />{lang.toUpperCase()}
            </button>
            <button onClick={toggleDark} className="p-2 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              {dark ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <a href="https://github.com/gmowses/secret-sharing" target="_blank" rel="noopener noreferrer" className="p-2 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            </a>
          </div>
        </div>
      </header>

      <main className="flex-1 px-6 py-10">
        <div className="max-w-4xl mx-auto space-y-8">
          <div>
            <h1 className="text-3xl font-bold">{t.title}</h1>
            <p className="mt-2 text-zinc-500 dark:text-zinc-400">{t.subtitle}</p>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 p-1 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 w-fit">
            {(['split','recover'] as const).map(tp => (
              <button key={tp} onClick={() => setTab(tp)} className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${tab===tp ? 'bg-white dark:bg-zinc-800 shadow-sm text-red-500 border border-zinc-200 dark:border-zinc-700' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'}`}>
                {tp === 'split' ? <Lock size={14} /> : <Unlock size={14} />}
                {tp === 'split' ? t.splitTab : t.recoverTab}
              </button>
            ))}
          </div>

          {tab === 'split' ? (
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Config */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-5">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">{t.secretLabel}</label>
                  <textarea value={secret} onChange={e => setSecret(e.target.value)} rows={4} placeholder={t.secretPlaceholder} spellCheck={false}
                    className="w-full rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50 px-3 py-2.5 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-red-500 transition-colors placeholder:text-zinc-400" />
                </div>

                {/* N slider */}
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="font-medium">{t.totalShares}</span>
                    <span className="font-bold text-red-500">{n}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <button onClick={() => setN(v => Math.max(k, Math.max(2, v-1)))} className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-sm font-bold hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors">-</button>
                    <input type="range" min={2} max={20} value={n} onChange={e => { const v=Number(e.target.value); setN(v); if(k>v) setK(v) }} className="h-1.5 w-full cursor-pointer accent-red-500" />
                    <button onClick={() => setN(v => Math.min(20, v+1))} className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-sm font-bold hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors">+</button>
                  </div>
                </div>

                {/* K slider */}
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <div>
                      <span className="font-medium">{t.threshold}</span>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400">{t.thresholdNote}</p>
                    </div>
                    <span className="font-bold text-red-500">{k}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <button onClick={() => setK(v => Math.max(2, v-1))} className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-sm font-bold hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors">-</button>
                    <input type="range" min={2} max={n} value={k} onChange={e => setK(Number(e.target.value))} className="h-1.5 w-full cursor-pointer accent-red-500" />
                    <button onClick={() => setK(v => Math.min(n, v+1))} className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-sm font-bold hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors">+</button>
                  </div>
                </div>

                {/* Schema visual */}
                <div className="flex items-center gap-2 flex-wrap">
                  {Array.from({length: n}, (_,i) => (
                    <div key={i} className={`w-8 h-8 rounded-full border-2 flex items-center justify-center text-xs font-bold transition-colors ${i < k ? 'border-red-500 bg-red-50 dark:bg-red-900/20 text-red-500' : 'border-zinc-200 dark:border-zinc-700 text-zinc-400'}`}>{i+1}</div>
                  ))}
                  <span className="text-xs text-zinc-400 ml-1">({k} of {n})</span>
                </div>

                {splitError && (
                  <div className="flex items-start gap-2 rounded-md border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 px-3 py-2 text-xs text-red-600 dark:text-red-400">
                    <AlertTriangle size={13} className="mt-0.5 shrink-0" />{splitError}
                  </div>
                )}

                <button onClick={handleSplit} className="w-full flex items-center justify-center gap-2 rounded-lg bg-red-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-red-600 transition-colors">
                  <Lock size={15} />{t.split}
                </button>
              </div>

              {/* Shares output */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 flex flex-col">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="font-semibold">{t.shares}</h2>
                    <p className="text-sm text-zinc-500 dark:text-zinc-400">{t.sharesDesc}</p>
                  </div>
                  {shares.length > 0 && (
                    <button onClick={copyAll} className="flex items-center gap-1.5 text-xs rounded-lg border border-zinc-200 dark:border-zinc-700 px-3 py-1.5 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
                      {copiedAll ? <Check size={12} className="text-red-500" /> : <Copy size={12} />}
                      {copiedAll ? t.copiedAll : t.copyAll}
                    </button>
                  )}
                </div>

                {shares.length === 0 ? (
                  <div className="flex-1 flex items-center justify-center rounded-lg border border-dashed border-zinc-200 dark:border-zinc-800 min-h-[200px]">
                    <div className="text-center text-zinc-400">
                      <Plus size={24} className="mx-auto mb-2 opacity-50" />
                      <p className="text-sm italic">{t.split} →</p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                    {shares.map((s, i) => (
                      <div key={i} className="group flex items-center gap-2 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-800/30 px-3 py-2">
                        <span className="shrink-0 w-6 h-6 rounded-full bg-red-100 dark:bg-red-900/30 text-red-500 text-xs font-bold flex items-center justify-center">{i+1}</span>
                        <span className="flex-1 font-mono text-[10px] break-all text-zinc-600 dark:text-zinc-400 select-all">{s}</span>
                        <button onClick={() => copyShare(i)} className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity text-zinc-400 hover:text-red-500">
                          {copiedIdx === i ? <Check size={13} className="text-red-500" /> : <Copy size={13} />}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Recover input */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium">{t.recoverLabel}</label>
                  <textarea value={recoverInput} onChange={e => { setRecoverInput(e.target.value); setRecoverError(''); setRecovered('') }} rows={10}
                    placeholder={t.recoverPlaceholder} spellCheck={false}
                    className="w-full rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50 px-3 py-2.5 font-mono text-xs resize-none focus:outline-none focus:ring-2 focus:ring-red-500 transition-colors placeholder:text-zinc-400" />
                </div>
                {recoverError && (
                  <div className="flex items-start gap-2 rounded-md border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 px-3 py-2 text-xs text-red-600 dark:text-red-400">
                    <AlertTriangle size={13} className="mt-0.5 shrink-0" />{recoverError}
                  </div>
                )}
                <button onClick={handleRecover} className="w-full flex items-center justify-center gap-2 rounded-lg bg-red-500 px-4 py-2.5 text-sm font-medium text-white hover:bg-red-600 transition-colors">
                  <Unlock size={15} />{t.recover}
                </button>

                {/* Helper: add share from split result */}
                {shares.length > 0 && (
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 space-y-2">
                    <p className="text-xs text-zinc-500 font-medium">Add from split result:</p>
                    <div className="flex flex-wrap gap-1">
                      {shares.map((s, i) => (
                        <button key={i} onClick={() => {
                          const lines = recoverInput.split('\n').filter(l => l.trim())
                          if (!lines.includes(s)) setRecoverInput(lines.concat(s).join('\n'))
                        }} className="px-2 py-0.5 rounded text-xs border border-zinc-200 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 font-mono transition-colors">
                          <Trash2 size={9} className="inline mr-1 text-zinc-400" />{t.share} {i+1}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Recovered output */}
              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4">
                <h2 className="font-semibold">{t.recovered}</h2>
                {recovered ? (
                  <>
                    <div className="flex items-start gap-2 rounded-lg border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20 px-3 py-2">
                      <CheckCircle size={15} className="text-green-500 mt-0.5 shrink-0" />
                      <p className="text-sm font-medium text-green-700 dark:text-green-400">Secret recovered successfully!</p>
                    </div>
                    <div className="relative group">
                      <div className="min-h-[80px] rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50 px-4 py-3 text-sm break-all select-all font-mono">{recovered}</div>
                      <button onClick={copyRecovered} className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity p-1.5 rounded-md text-zinc-400 hover:bg-zinc-200 dark:hover:bg-zinc-700">
                        {copiedRecovered ? <Check size={13} className="text-red-500" /> : <Copy size={13} />}
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-200 dark:border-zinc-800 min-h-[200px] text-zinc-400">
                    <Unlock size={24} className="mb-2 opacity-50" />
                    <p className="text-sm italic">{t.recover} →</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* How it works */}
          <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 space-y-2">
            <h2 className="font-semibold text-red-500">{t.howTitle}</h2>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">{t.howText}</p>
          </div>

          <p className="text-[10px] text-zinc-400">{t.notice}</p>
        </div>
      </main>

      <footer className="border-t border-zinc-200 dark:border-zinc-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between text-xs text-zinc-400">
          <span>{t.builtBy} <a href="https://github.com/gmowses" className="text-zinc-600 dark:text-zinc-300 hover:text-red-500 transition-colors">Gabriel Mowses</a></span>
          <span>MIT License</span>
        </div>
      </footer>
    </div>
  )
}
