import { Currency, ExchangeRates, CurrencyFormatOptions } from '@/types/geography';

export class CurrencyService {
  private static readonly CACHE_KEY = 'exchange_rates';
  private static readonly CACHE_DURATION = 60 * 60 * 1000; // 1 hour
  private static readonly BASE_CURRENCY = 'EUR';

  // Fallback exchange rates (1 EUR = X currency)
  private static readonly FALLBACK_RATES: ExchangeRates = {
    EUR: 1,
    USD: 1.08,
    MAD: 10.95, // 1 EUR ≈ 11 MAD
    DZD: 145.50, // 1 EUR ≈ 145 DZD
    TND: 3.35, // 1 EUR ≈ 3.35 TND
  };

  static async getExchangeRates(): Promise<ExchangeRates> {
    // Check cache first
    const cached = this.getCachedRates();
    if (cached) {
      return cached;
    }

    try {
      // Try free exchangerate-api.io service
      const response = await fetch(`https://api.exchangerate-api.com/v4/latest/${this.BASE_CURRENCY}`);
      
      if (!response.ok) {
        throw new Error('Exchange rate service unavailable');
      }

      const data = await response.json();
      const rates: ExchangeRates = {
        EUR: 1,
        USD: data.rates.USD || this.FALLBACK_RATES.USD,
        MAD: data.rates.MAD || this.FALLBACK_RATES.MAD,
        DZD: data.rates.DZD || this.FALLBACK_RATES.DZD,
        TND: data.rates.TND || this.FALLBACK_RATES.TND,
      };

      // Cache the result
      this.cacheRates(rates);
      
      return rates;
    } catch (error) {
      console.warn('Failed to fetch exchange rates, using fallback:', error);
      return this.FALLBACK_RATES;
    }
  }

  static convertPrice(amount: number, fromCurrency: Currency, toCurrency: Currency, rates: ExchangeRates): number {
    if (fromCurrency === toCurrency) return amount;
    
    const fromRate = rates[fromCurrency] || 1;
    const toRate = rates[toCurrency] || 1;
    
    // Since our rates are 1 EUR = X currency, we convert:
    // amount (in fromCurrency) -> EUR -> toCurrency
    if (fromCurrency === 'EUR') {
      // From EUR to other currency: multiply by target rate
      return amount * toRate;
    } else if (toCurrency === 'EUR') {
      // From other currency to EUR: divide by source rate
      return amount / fromRate;
    } else {
      // From one non-EUR currency to another: go through EUR
      const eurAmount = amount / fromRate;
      return eurAmount * toRate;
    }
  }

  static formatPrice(amount: number, options: CurrencyFormatOptions): string {
    const { currency, locale, symbol } = options;
    
    try {
      // For Maghreb currencies, use custom formatting
      if (['MAD', 'DZD', 'TND'].includes(currency)) {
        const roundedAmount = Math.round(amount);
        // Format with thousands separator using the locale
        const formatter = new Intl.NumberFormat(locale, {
          minimumFractionDigits: 0,
          maximumFractionDigits: 0,
        });
        return `${formatter.format(roundedAmount)} ${symbol}`;
      }
      
      // Use Intl.NumberFormat for EUR and USD
      const formatter = new Intl.NumberFormat(locale, {
        style: 'currency',
        currency: currency,
        minimumFractionDigits: 0,
        maximumFractionDigits: 0,
      });

      return formatter.format(amount);
    } catch (error) {
      // Fallback formatting
      const roundedAmount = Math.round(amount);
      return `${roundedAmount} ${symbol}`;
    }
  }

  private static getCachedRates(): ExchangeRates | null {
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
      console.warn('Failed to read cached rates:', error);
      return null;
    }
  }

  private static cacheRates(rates: ExchangeRates): void {
    try {
      const cacheData = {
        data: rates,
        timestamp: Date.now(),
      };
      localStorage.setItem(this.CACHE_KEY, JSON.stringify(cacheData));
    } catch (error) {
      console.warn('Failed to cache rates:', error);
    }
  }
}