import { Component, type ReactNode } from 'react'

import { Button } from '@/components/ui/button'

interface RouteErrorBoundaryProps {
  children: ReactNode
}

interface RouteErrorBoundaryState {
  failed: boolean
}

export class RouteErrorBoundary extends Component<
  RouteErrorBoundaryProps,
  RouteErrorBoundaryState
> {
  state: RouteErrorBoundaryState = { failed: false }

  static getDerivedStateFromError(): RouteErrorBoundaryState {
    return { failed: true }
  }

  private reset = () => {
    this.setState({ failed: false })
  }

  render() {
    if (!this.state.failed) {
      return this.props.children
    }

    return (
      <main className="grid min-h-[60vh] place-items-center p-6">
        <section
          aria-labelledby="unexpected-error-title"
          className="max-w-lg rounded-xl border bg-card p-6 shadow-sm"
          role="alert"
        >
          <h1 className="text-xl font-semibold" id="unexpected-error-title">
            Something went wrong
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            The page encountered an unexpected error. Try again, or navigate to
            another page if the problem continues.
          </p>
          <Button className="mt-4" onClick={this.reset} type="button">
            Try again
          </Button>
        </section>
      </main>
    )
  }
}
