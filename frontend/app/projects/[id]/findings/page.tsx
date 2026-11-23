"use client"

import { useEffect, useState } from "react"
import { apiFetch } from "@/lib/api";
import { useParams, useRouter } from "next/navigation"
import Link from "next/link"

interface Finding {
  id: string
  title: string
  algorithm: string
  severity: string
  file_path: string
  line: number
  quantum_vulnerable: boolean
  recommendation: string
}

export default function FindingsPage() {
  const params = useParams()
  const router = useRouter()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (params.id) {
      fetchFindings()
    }
  }, [params.id])

  const fetchFindings = async () => {
    try {
      const response = await apiFetch(`/api/findings?project_id=${params.id}`)
      const data = await response.json()
      // Ensure data is an array
      setFindings(Array.isArray(data) ? data : [])
    } catch (error) {
      console.error("Failed to fetch findings:", error)
      setFindings([])
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
          <h1 className="text-3xl font-bold text-foreground mt-2">Findings</h1>
          <p className="text-muted-foreground">Cryptographic vulnerabilities and issues</p>
        </div>

        {findings.length === 0 ? (
          <div className="p-6 border border-border rounded-lg bg-card text-muted-foreground">
            No findings yet. Run a scan to detect cryptographic issues.
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <div key={finding.id} className="p-6 border border-border rounded-lg bg-card">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-foreground">{finding.title}</h3>
                    <div className="text-sm text-muted-foreground mt-1">
                      {finding.file_path}:{finding.line}
                    </div>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-medium ${
                      finding.severity === "critical"
                        ? "bg-red-100 text-red-800"
                        : finding.severity === "high"
                        ? "bg-orange-100 text-orange-800"
                        : finding.severity === "medium"
                        ? "bg-yellow-100 text-yellow-800"
                        : "bg-blue-100 text-blue-800"
                    }`}
                  >
                    {finding.severity}
                  </span>
                </div>
                <div className="space-y-2">
                  <div className="text-sm">
                    <span className="text-muted-foreground">Algorithm:</span>{" "}
                    <span className="text-foreground font-medium">{finding.algorithm}</span>
                  </div>
                  {finding.quantum_vulnerable && (
                    <div className="text-sm text-red-600 font-medium">
                      ⚠️ Quantum Vulnerable
                    </div>
                  )}
                  {finding.recommendation && (
                    <div className="text-sm">
                      <span className="text-muted-foreground">Recommendation:</span>{" "}
                      <span className="text-foreground">{finding.recommendation}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
