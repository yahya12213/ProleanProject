import React, { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'

interface NavigationState {
  history: string[]
  breadcrumbs: Array<{ label: string; path: string }>
  canGoBack: boolean
}

interface NavigationContextType {
  navigationState: NavigationState
  goBack: () => void
  goToPage: (path: string, label?: string) => void
  setBreadcrumbs: (breadcrumbs: Array<{ label: string; path: string }>) => void
  getReturnPath: () => string
  clearHistory: () => void
}

const NavigationContext = createContext<NavigationContextType | undefined>(undefined)

export const NavigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate()
  const location = useLocation()
  
  const [navigationState, setNavigationState] = useState<NavigationState>({
    history: [location.pathname],
    breadcrumbs: [],
    canGoBack: false
  })

  // Sync with browser history and detect navigation changes
  useEffect(() => {
    const currentPath = location.pathname
    setNavigationState(prev => {
      // Don't add duplicate paths
      if (prev.history[prev.history.length - 1] === currentPath) {
        return prev
      }
      
      const newHistory = [...prev.history, currentPath].slice(-20) // Keep last 20 pages
      return {
        ...prev,
        history: newHistory,
        canGoBack: newHistory.length > 1
      }
    })
  }, [location.pathname])

  // Generate smart breadcrumbs based on current path
  useEffect(() => {
    const generateBreadcrumbs = (path: string) => {
      const segments = path.split('/').filter(Boolean)
      const breadcrumbs: Array<{ label: string; path: string }> = [
        { label: 'Accueil', path: '/dashboard' }
      ]

      let currentPath = ''
      for (const segment of segments) {
        currentPath += `/${segment}`
        
        let label = segment.charAt(0).toUpperCase() + segment.slice(1)
        
        // Smart labeling based on known routes
        switch (segment) {
          case 'administration':
            label = 'Administration'
            break
          case 'hub-gestion':
            label = 'Hub de Gestion'
            break
          case 'mon-espace':
            label = 'Mon Espace'
            break
          case 'formations':
            label = 'Formations'
            break
          case 'classes':
            label = 'Classes'
            break
          case 'inscriptions':
            label = 'Inscriptions'
            break
          case 'employee':
            label = 'Employé'
            break
          default:
            // Check if it's an ID (UUID pattern)
            if (segment.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
              label = 'Détails'
            }
        }
        
        breadcrumbs.push({ label, path: currentPath })
      }
      
      return breadcrumbs
    }

    const breadcrumbs = generateBreadcrumbs(location.pathname)
    setNavigationState(prev => ({
      ...prev,
      breadcrumbs
    }))
  }, [location.pathname])

  const goBack = useCallback(() => {
    if (navigationState.history.length > 1) {
      // Remove current page and go to previous
      const newHistory = navigationState.history.slice(0, -1)
      const previousPath = newHistory[newHistory.length - 1]
      
      setNavigationState(prev => ({
        ...prev,
        history: newHistory,
        canGoBack: newHistory.length > 1
      }))
      
      navigate(previousPath)
    } else {
      // Fallback to dashboard if no history
      navigate('/dashboard')
    }
  }, [navigate, navigationState.history])

  const goToPage = useCallback((path: string, label?: string) => {
    navigate(path)
  }, [navigate])

  const setBreadcrumbs = useCallback((breadcrumbs: Array<{ label: string; path: string }>) => {
    setNavigationState(prev => ({
      ...prev,
      breadcrumbs
    }))
  }, [])

  const getReturnPath = useCallback(() => {
    if (navigationState.history.length > 1) {
      return navigationState.history[navigationState.history.length - 2]
    }
    return '/dashboard'
  }, [navigationState.history])

  const clearHistory = useCallback(() => {
    setNavigationState(prev => ({
      ...prev,
      history: [location.pathname],
      canGoBack: false
    }))
  }, [location.pathname])

  return (
    <NavigationContext.Provider value={{
      navigationState,
      goBack,
      goToPage,
      setBreadcrumbs,
      getReturnPath,
      clearHistory
    }}>
      {children}
    </NavigationContext.Provider>
  )
}

export const useNavigation = () => {
  const context = useContext(NavigationContext)
  if (context === undefined) {
    throw new Error('useNavigation must be used within a NavigationProvider')
  }
  return context
}