"use client"

import { useEffect, useState } from "react"
import { apiFetch } from "@/lib/api";
import { useParams } from "next/navigation"
import Link from "next/link"

interface Recommendation {
  id: string
  algorithm: string
  candidate_pqc: string
  recommendation: string
  migration_notes: string
  why_it_matters: string
}

export default function RecommendationsPage() {
  const params = useParams()
  const [recommendations, setRecommendations] = useState<Recommendation[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (params.id) {
      fetchRecommendations()
    }
  }, [params.id])

  const fetchRecommendations = async () => {
    try {
      const response = await apiFetch(`/api/recommendations/project/${params.id}`)
      const data = await response.json()
      // Ensure data is an array
      setRecommendations(Array.isArray(data) ? data : [])
    } catch (error) {
      console.error("Failed to fetch recommendations:", error)
      setRecommendations([])
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
          <h1 className="text-3xl font-bold text-foreground mt-2">Recommendations</h1>
          <p className="text-muted-foreground">PQC migration recommendations</p>
        </div>

        {recommendations.length === 0 ? (
          <div className="p-6 border border-border rounded-lg bg-card text-muted-foreground">
            No recommendations available. Run a scan first.
          </div>
        ) : (
          <div className="space-y-4">
            {recommendations.map((rec) => (
              <div key={rec.id} className="p-6 border border-border rounded-lg bg-card">
                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-foreground">{rec.algorithm}</h3>
                  <div className="text-sm text-muted-foreground mt-1">
                    Recommended: <span className="text-foreground font-medium">{rec.candidate_pqc}</span>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <div className="text-sm font-medium text-foreground mb-1">Recommendation</div>
                    <div className="text-sm text-muted-foreground">{rec.recommendation}</div>
                  </div>
                  {rec.migration_notes && (
                    <div>
                      <div className="text-sm font-medium text-foreground mb-1">Migration Notes</div>
                      <div className="text-sm text-muted-foreground">{rec.migration_notes}</div>
                    </div>
                  )}
                  <div>
                    <div className="text-sm font-medium text-foreground mb-1">Why It Matters</div>
                    <div className="text-sm text-muted-foreground">{rec.why_it_matters}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
