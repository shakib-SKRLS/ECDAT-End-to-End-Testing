import { redirect } from "next/navigation"

export default function Home() {
  redirect("/dashboard")
  return (
    <main className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-4xl font-bold text-foreground mb-4">
          ECDAT
        </h1>
        <p className="text-muted-foreground text-lg">
          Enterprise Cryptographic Discovery & Analysis Tool
        </p>
        <div className="mt-8 p-6 border border-border rounded-lg bg-card">
          <p className="text-sm text-muted-foreground">
            Frontend initialized. Backend API integration pending.
          </p>
        </div>
      </div>
    </main>
  )
}
