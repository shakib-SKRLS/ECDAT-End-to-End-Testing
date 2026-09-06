"use client"

import { useEffect, useState } from "react"
import { useParams } from "next/navigation"
import Link from "next/link"

interface RiskAssessment {
  id: string
  overall_score: number
  overall_category: string
  quantum_readiness: string
  mosca_urgent: boolean
  mosca_explanation: string
}

export default function RiskPage() {
  const params = useParams()
  const [risk, setRisk] = useState<RiskAssessment | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (params.id) {
      fetchRisk()
    }
  }, [params.id])

  const fetchRisk = async () => {
    try {
      const response = await fetch(`http://localhost:8000/api/risk/project/${params.id}`)
      if (!response.ok) {
        setRisk(null)
        return
      }
      const data = await response.json()
      setRisk(data)
    } catch (error) {
      console.error("Failed to fetch risk:", error)
      setRisk(null)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="min-h-screen bg-background p-8">Loading...</div>
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <Link href={`/projects/${params.id}`} className="text-sm text-muted-foreground hover:text-foreground">
            ← Back to Project
          </Link>
          <h1 className="text-3xl font-bold text-foreground mt-2">Risk Assessment</h1>
          <p className="text-muted-foreground">Overall risk and quantum readiness</p>
        </div>

        {!risk ? (
          <div className="p-6 border border-border rounded-lg bg-card text-muted-foreground">
            No risk assessment available. Run a scan first.
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-6 border border-border rounded-lg bg-card">
                <div className="text-sm text-muted-foreground mb-2">Overall Risk Score</div>
                <div className="text-4xl font-bold text-foreground">{risk.overall_score}/100</div>
                <div className="text-lg font-semibold mt-2 capitalize">{risk.overall_category}</div>
              </div>
              <div className="p-6 border border-border rounded-lg bg-card">
                <div className="text-sm text-muted-foreground mb-2">Quantum Readiness</div>
                <div className="text-2xl font-bold text-foreground capitalize">{risk.quantum_readiness}</div>
              </div>
            </div>

            <div className="p-6 border border-border rounded-lg bg-card">
              <h3 className="text-lg font-semibold text-foreground mb-4">Mosca Timeline Analysis</h3>
              {risk.mosca_urgent ? (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                  <div className="text-red-800 font-semibold mb-2">⚠️ URGENT: Quantum Migration Required</div>
                  <div className="text-sm text-red-700">{risk.mosca_explanation}</div>
                </div>
              ) : (
                <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                  <div className="text-green-800 font-semibold mb-2">✓ No Immediate Action Required</div>
                  <div className="text-sm text-green-700">{risk.mosca_explanation}</div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
