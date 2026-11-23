"use client"

import { useEffect, useState } from "react"
import { apiFetch } from "@/lib/api";
import { useParams, useRouter } from "next/navigation"
import Link from "next/link"

interface Project {
  id: string
  name: string
  description: string
  business_criticality: number
  data_lifetime_years: number
  migration_time_years: number
  exposure: string
}

interface Scan {
  id: string
  status: string
  progress: number
  files_scanned: number
  findings_count: number
  created_at: string
}

export default function ProjectPage() {
  const params = useParams()
  const router = useRouter()
  const [project, setProject] = useState<Project | null>(null)
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (params.id) {
      fetchProject()
      fetchScans()
    }
  }, [params.id])

  const fetchProject = async () => {
    try {
      const response = await apiFetch(`/api/projects/${params.id}`)
      const data = await response.json()
      setProject(data)
    } catch (error) {
      console.error("Failed to fetch project:", error)
    }
  }

  const fetchScans = async () => {
    try {
      const response = await apiFetch(`/api/scans?skip=0&limit=10`)
      const data = await response.json()
      setScans(data.filter((s: Scan) => s.project_id === params.id))
    } catch (error) {
      console.error("Failed to fetch scans:", error)
    } finally {
      setLoading(false)
    }
  }

  const startScan = async () => {
    try {
      const response = await apiFetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: params.id,
          source_type: "local_dir",
          source_location: "../fixtures/vulnerable-project",
        }),
      })
      if (response.ok) {
        fetchScans()
      }
    } catch (error) {
      console.error("Failed to start scan:", error)
    }
  }

  if (loading) {
    return <div className="min-h-screen bg-background p-8">Loading...</div>
  }

  if (!project) {
    return <div className="min-h-screen bg-background p-8">Project not found</div>
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <div>
            <Link href="/dashboard" className="text-sm text-muted-foreground hover:text-foreground">
              ← Back to Dashboard
            </Link>
            <h1 className="text-3xl font-bold text-foreground mt-2">{project.name}</h1>
            <p className="text-muted-foreground">{project.description}</p>
          </div>
          <button
            onClick={startScan}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            Start Scan
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="p-4 border border-border rounded-lg bg-card">
            <div className="text-sm text-muted-foreground">Criticality</div>
            <div className="text-2xl font-bold text-foreground">{project.business_criticality}/5</div>
          </div>
          <div className="p-4 border border-border rounded-lg bg-card">
            <div className="text-sm text-muted-foreground">Data Lifetime</div>
            <div className="text-2xl font-bold text-foreground">{project.data_lifetime_years}y</div>
          </div>
          <div className="p-4 border border-border rounded-lg bg-card">
            <div className="text-sm text-muted-foreground">Exposure</div>
            <div className="text-2xl font-bold text-foreground capitalize">{project.exposure}</div>
          </div>
        </div>

        <div className="border border-border rounded-lg bg-card mb-8">
          <div className="p-6 border-b border-border">
            <h2 className="text-xl font-semibold">Recent Scans</h2>
          </div>
          {scans.length === 0 ? (
            <div className="p-6 text-muted-foreground">No scans yet. Start a scan to begin analysis.</div>
          ) : (
            <div className="divide-y divide-border">
              {scans.map((scan) => (
                <div key={scan.id} className="p-6">
                  <div className="flex justify-between items-center">
                    <div>
                      <div className="font-semibold text-foreground capitalize">{scan.status}</div>
                      <div className="text-sm text-muted-foreground">
                        {new Date(scan.created_at).toLocaleString()}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm text-muted-foreground">{scan.files_scanned} files</div>
                      <div className="text-sm text-muted-foreground">{scan.findings_count} findings</div>
                    </div>
                  </div>
                  {scan.status === "running" && (
                    <div className="mt-4">
                      <div className="w-full bg-muted rounded-full h-2">
                        <div
                          className="bg-primary h-2 rounded-full transition-all"
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Link
            href={`/projects/${params.id}/findings`}
            className="p-6 border border-border rounded-lg bg-card hover:bg-muted/50 transition-colors"
          >
            <h3 className="text-lg font-semibold text-foreground mb-2">Findings</h3>
            <p className="text-sm text-muted-foreground">View cryptographic vulnerabilities and issues</p>
          </Link>
          <Link
            href={`/projects/${params.id}/risk`}
            className="p-6 border border-border rounded-lg bg-card hover:bg-muted/50 transition-colors"
          >
            <h3 className="text-lg font-semibold text-foreground mb-2">Risk Assessment</h3>
            <p className="text-sm text-muted-foreground">View overall risk and quantum readiness</p>
          </Link>
          <Link
            href={`/projects/${params.id}/recommendations`}
            className="p-6 border border-border rounded-lg bg-card hover:bg-muted/50 transition-colors"
          >
            <h3 className="text-lg font-semibold text-foreground mb-2">Recommendations</h3>
            <p className="text-sm text-muted-foreground">View PQC migration recommendations</p>
          </Link>
          <Link
            href={`/projects/${params.id}/cbom`}
            className="p-6 border border-border rounded-lg bg-card hover:bg-muted/50 transition-colors"
          >
            <h3 className="text-lg font-semibold text-foreground mb-2">CBOM</h3>
            <p className="text-sm text-muted-foreground">View Cryptographic Bill of Materials</p>
          </Link>
        </div>
      </div>
    </div>
  )
}
