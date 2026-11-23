"use client"

import { useEffect, useState } from "react"
import { apiFetch } from "@/lib/api";
import Link from "next/link"

interface Project {
  id: string
  name: string
  description: string
  created_at: string
}

export default function DashboardPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchProjects()
  }, [])

  const fetchProjects = async () => {
    try {
      const response = await apiFetch("/api/projects")
      const data = await response.json()
      setProjects(data)
    } catch (error) {
      console.error("Failed to fetch projects:", error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-4xl font-bold text-foreground mb-2">ECDAT Dashboard</h1>
            <p className="text-muted-foreground">Enterprise Cryptographic Discovery & Analysis Tool</p>
          </div>
          <Link
            href="/projects/new"
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            New Project
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="p-6 border border-border rounded-lg bg-card">
            <div className="text-3xl font-bold text-foreground">{projects.length}</div>
            <div className="text-sm text-muted-foreground">Total Projects</div>
          </div>
          <div className="p-6 border border-border rounded-lg bg-card">
            <div className="text-3xl font-bold text-foreground">0</div>
            <div className="text-sm text-muted-foreground">Crypto Assets</div>
          </div>
          <div className="p-6 border border-border rounded-lg bg-card">
            <div className="text-3xl font-bold text-destructive">0</div>
            <div className="text-sm text-muted-foreground">Critical Findings</div>
          </div>
          <div className="p-6 border border-border rounded-lg bg-card">
            <div className="text-3xl font-bold text-foreground">0%</div>
            <div className="text-sm text-muted-foreground">Quantum Ready</div>
          </div>
        </div>

        <div className="border border-border rounded-lg bg-card">
          <div className="p-6 border-b border-border">
            <h2 className="text-xl font-semibold">Projects</h2>
          </div>
          {loading ? (
            <div className="p-6 text-muted-foreground">Loading...</div>
          ) : projects.length === 0 ? (
            <div className="p-6 text-muted-foreground">
              No projects yet. Create your first project to get started.
            </div>
          ) : (
            <div className="divide-y divide-border">
              {projects.map((project) => (
                <Link
                  key={project.id}
                  href={`/projects/${project.id}`}
                  className="block p-6 hover:bg-muted/50 transition-colors"
                >
                  <div className="font-semibold text-foreground">{project.name}</div>
                  <div className="text-sm text-muted-foreground mt-1">{project.description}</div>
                  <div className="text-xs text-muted-foreground mt-2">
                    Created: {new Date(project.created_at).toLocaleDateString()}
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
