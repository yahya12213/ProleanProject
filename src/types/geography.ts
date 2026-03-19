export type Language = 'fr' | 'en' | 'ar';
export type Currency = 'EUR' | 'USD' | 'MAD' | 'DZD' | 'TND';

export interface CountryConfig {
  code: string;
  name: string;
  languages: Language[];
  defaultLanguage: Language;
  currency: Currency;
  currencySymbol: string;
  rtl?: boolean;
}

export interface GeolocationData {
  country: string;
  countryCode: string;
  currency?: string;
  languages?: string[];
}

export interface ExchangeRates {
  [key: string]: number;
}

export interface CurrencyFormatOptions {
  currency: Currency;
  locale: string;
  symbol: string;
}