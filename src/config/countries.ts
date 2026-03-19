import { CountryConfig } from '@/types/geography';

export const COUNTRY_CONFIGS: Record<string, CountryConfig> = {
  MA: {
    code: 'MA',
    name: 'Morocco',
    languages: ['fr', 'ar', 'en'],
    defaultLanguage: 'fr',
    currency: 'MAD',
    currencySymbol: 'DH',
    rtl: false, // French is default, so LTR by default
  },
  FR: {
    code: 'FR',
    name: 'France',
    languages: ['fr', 'en'],
    defaultLanguage: 'fr',
    currency: 'EUR',
    currencySymbol: '€',
  },
  DZ: {
    code: 'DZ',
    name: 'Algeria',
    languages: ['fr', 'ar', 'en'],
    defaultLanguage: 'fr',
    currency: 'DZD',
    currencySymbol: 'DA',
    rtl: false,
  },
  TN: {
    code: 'TN',
    name: 'Tunisia',
    languages: ['fr', 'ar', 'en'],
    defaultLanguage: 'fr',
    currency: 'TND',
    currencySymbol: 'TND',
    rtl: false,
  },
  US: {
    code: 'US',
    name: 'United States',
    languages: ['en', 'fr'],
    defaultLanguage: 'en',
    currency: 'USD',
    currencySymbol: '$',
  },
  GB: {
    code: 'GB',
    name: 'United Kingdom',
    languages: ['en', 'fr'],
    defaultLanguage: 'en',
    currency: 'USD', // Using USD as base for simplicity
    currencySymbol: '$',
  },
  // Default fallback
  DEFAULT: {
    code: 'DEFAULT',
    name: 'Default',
    languages: ['fr', 'en'],
    defaultLanguage: 'fr',
    currency: 'EUR',
    currencySymbol: '€',
  },
};

export const getCountryConfig = (countryCode: string): CountryConfig => {
  return COUNTRY_CONFIGS[countryCode] || COUNTRY_CONFIGS.DEFAULT;
};