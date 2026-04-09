interface ScoreGaugeProps {
  score: number
}

export default function ScoreGauge({ score }: ScoreGaugeProps) {
  const size = 60
  const stroke = 5
  const radius = (size - stroke) / 2
  const circumference = radius * 2 * Math.PI
  const offset = circumference - (score / 100) * circumference

  const getColor = (s: number) => {
    if (s >= 80) return 'text-green-500'
    if (s >= 50) return 'text-yellow-500'
    return 'text-red-500'
  }

  const getBgColor = (s: number) => {
    if (s >= 80) return 'bg-green-50'
    if (s >= 50) return 'bg-yellow-50'
    return 'bg-red-50'
  }

  return (
    <div className={`relative flex items-center justify-center rounded-2xl p-4 ${getBgColor(score)} border border-white/50 shadow-sm transition-all hover:scale-105`}>
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={stroke}
          fill="transparent"
          className="text-gray-200"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={stroke}
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className={`${getColor(score)} transition-all duration-1000 ease-out`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-lg font-bold leading-none ${getColor(score)}`}>
          {score}
        </span>
        <span className="text-[10px] text-gray-400 font-medium uppercase tracking-tight">Score</span>
      </div>
    </div>
  )
}