"use client"

import { useState } from "react"
import { apiFetch } from "@/lib/api";
import { useRouter } from "next/navigation"

export default function NewProjectPage() {
  const router = useRouter()
  const [formData, setFormData] = useState({
    name: "",
    description: "",
    business_criticality: 3,
    data_lifetime_years: 5.0,
    migration_time_years: 3.0,
    exposure: "internal",
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const response = await apiFetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      })
      if (response.ok) {
        const project = await response.json()
        router.push(`/projects/${project.id}`)
      }
    } catch (error) {
      console.error("Failed to create project:", error)
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8 max-w-2xl">
        <h1 className="text-3xl font-bold text-foreground mb-6">Create New Project</h1>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Project Name</label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
              rows={3}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Business Criticality (1-5)</label>
            <input
              type="number"
              min="1"
              max="5"
              value={formData.business_criticality}
              onChange={(e) => setFormData({ ...formData, business_criticality: parseInt(e.target.value) })}
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Data Lifetime (years)</label>
            <input
              type="number"
              step="0.1"
              value={formData.data_lifetime_years}
              onChange={(e) => setFormData({ ...formData, data_lifetime_years: parseFloat(e.target.value) })}
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Migration Time (years)</label>
            <input
              type="number"
              step="0.1"
              value={formData.migration_time_years}
              onChange={(e) => setFormData({ ...formData, migration_time_years: parseFloat(e.target.value) })}
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Exposure</label>
            <select
              value={formData.exposure}
              onChange={(e) => setFormData({ ...formData, exposure: e.target.value })}
              className="w-full px-3 py-2 border border-border rounded-md bg-background text-foreground"
            >
              <option value="internal">Internal</option>
              <option value="public">Public</option>
              <option value="airgapped">Air-gapped</option>
            </select>
          </div>

          <div className="flex gap-4">
            <button
              type="submit"
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
            >
              Create Project
            </button>
            <button
              type="button"
              onClick={() => router.back()}
              className="px-4 py-2 border border-border rounded-md hover:bg-muted"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
