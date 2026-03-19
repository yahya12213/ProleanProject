import { GeolocationData } from '@/types/geography';

export class GeolocationService {
  private static readonly CACHE_KEY = 'user_geolocation';
  private static readonly CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

  static async detectUserLocation(): Promise<GeolocationData | null> {
    // Check cache first
    const cached = this.getCachedLocation();
    if (cached) {
      return cached;
    }

    try {
      // Try browser's geolocation API first (more reliable)
      if (navigator.geolocation) {
        const position = await new Promise<GeolocationPosition>((resolve, reject) => {
          navigator.geolocation.getCurrentPosition(resolve, reject, {
            timeout: 5000,
            enableHighAccuracy: false
          });
        });
        
        // For now, return default location as we can't easily convert coordinates to country
        const locationData: GeolocationData = {
          country: 'Maroc',
          countryCode: 'MA',
          currency: 'MAD',
          languages: ['fr', 'ar'],
        };
        
        this.cacheLocation(locationData);
        return locationData;
      }
      
      // Fallback to default Morocco location
      const locationData: GeolocationData = {
        country: 'Maroc',
        countryCode: 'MA',
        currency: 'MAD',
        languages: ['fr', 'ar'],
      };
      
      this.cacheLocation(locationData);
      return locationData;
      
    } catch (error) {
      console.warn('Failed to detect user location:', error);
      
      // Return default Morocco location as final fallback
      const defaultLocation: GeolocationData = {
        country: 'Maroc',
        countryCode: 'MA',
        currency: 'MAD',
        languages: ['fr', 'ar'],
      };
      
      this.cacheLocation(defaultLocation);
      return defaultLocation;
    }
  }

  private static getCachedLocation(): GeolocationData | null {
    try {
      const cached = localStorage.getItem(this.CACHE_KEY);
      if (!cached) return null;

      const parsed = JSON.parse(cached);
      const now = Date.now();
      
      if (now - parsed.timestamp > this.CACHE_DURATION) {
        localStorage.removeItem(this.CACHE_KEY);
        return null;
      }

      return parsed.data;
    } catch (error) {
      console.warn('Failed to read cached location:', error);
      return null;
    }
  }

  private static cacheLocation(data: GeolocationData): void {
    try {
      const cacheData = {
        data,
        timestamp: Date.now(),
      };
      localStorage.setItem(this.CACHE_KEY, JSON.stringify(cacheData));
    } catch (error) {
      console.warn('Failed to cache location:', error);
    }
  }
}