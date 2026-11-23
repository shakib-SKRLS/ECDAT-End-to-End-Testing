"use client"

import { useEffect, useState } from "react"
import { apiFetch } from "@/lib/api";
import { useParams } from "next/navigation"
import Link from "next/link"

interface Asset {
  id: string
  algorithm: string
  algorithm_family: string
  primitive_type: string
  key_size?: number
  curve?: string
  mode?: string
  file_path: string
  line: number
  severity: string
  quantum_vulnerable: boolean
  classification: string
}

export default function CBOMPage() {
  const params = useParams()
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (params.id) {
      fetchAssets()
    }
  }, [params.id])

  const fetchAssets = async () => {
    try {
      const response = await apiFetch(`/api/assets?project_id=${params.id}`)
      const data = await response.json()
      // Ensure data is an array
      setAssets(Array.isArray(data) ? data : [])
    } catch (error) {
      console.error("Failed to fetch assets:", error)
      setAssets([])
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
          <h1 className="text-3xl font-bold text-foreground mt-2">Cryptographic Bill of Materials (CBOM)</h1>
          <p className="text-muted-foreground">Complete inventory of cryptographic assets</p>
        </div>

        {assets.length === 0 ? (
          <div className="p-6 border border-border rounded-lg bg-card text-muted-foreground">
            No CBOM data available. Run a scan first.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left p-3 text-sm font-semibold text-foreground">Algorithm</th>
                  <th className="text-left p-3 text-sm font-semibold text-foreground">Family</th>
                  <th className="text-left p-3 text-sm font-semibold text-foreground">Type</th>
                  <th className="text-left p-3 text-sm font-semibold text-foreground">Key Size</th>
                  <th className="text-left p-3 text-sm font-semibold text-foreground">Location</th>
                  <th className="text-left p-3 text-sm font-semibold text-foreground">Severity</th>
                  <th className="text-left p-3 text-sm font-semibold text-foreground">Quantum</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.id} className="border-b border-border hover:bg-muted/50">
                    <td className="p-3 text-sm text-foreground font-medium">{asset.algorithm}</td>
                    <td className="p-3 text-sm text-muted-foreground">{asset.algorithm_family}</td>
                    <td className="p-3 text-sm text-muted-foreground">{asset.primitive_type}</td>
                    <td className="p-3 text-sm text-muted-foreground">
                      {asset.key_size || asset.curve || asset.mode || "-"}
                    </td>
                    <td className="p-3 text-sm text-muted-foreground">
                      {asset.file_path}:{asset.line}
                    </td>
                    <td className="p-3 text-sm">
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${
                          asset.severity === "critical"
                            ? "bg-red-100 text-red-800"
                            : asset.severity === "high"
                            ? "bg-orange-100 text-orange-800"
                            : asset.severity === "medium"
                            ? "bg-yellow-100 text-yellow-800"
                            : "bg-blue-100 text-blue-800"
                        }`}
                      >
                        {asset.severity}
                      </span>
                    </td>
                    <td className="p-3 text-sm">
                      {asset.quantum_vulnerable ? (
                        <span className="text-red-600 font-medium">Yes</span>
                      ) : (
                        <span className="text-green-600">No</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
