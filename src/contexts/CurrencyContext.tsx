import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Currency, ExchangeRates, CurrencyFormatOptions } from '@/types/geography';
import { CurrencyService } from '@/services/currency';

interface CurrencyContextType {
  currency: Currency;
  setCurrency: (currency: Currency) => void;
  rates: ExchangeRates;
  convertPrice: (amount: number, fromCurrency?: Currency) => number;
  formatPrice: (amount: number, fromCurrency?: Currency) => string;
  getCurrencySymbol: () => string;
  isLoading: boolean;
}

const CurrencyContext = createContext<CurrencyContextType | undefined>(undefined);

const CURRENCY_SYMBOLS: Record<Currency, string> = {
  EUR: '€',
  USD: '$',
  MAD: 'DH',
  DZD: 'DA',
  TND: 'TND',
};

const CURRENCY_LOCALES: Record<Currency, string> = {
  EUR: 'fr-FR',
  USD: 'en-US',
  MAD: 'fr-MA',
  DZD: 'fr-DZ',
  TND: 'fr-TN',
};

interface CurrencyProviderProps {
  children: ReactNode;
  defaultCurrency?: Currency;
}

export const CurrencyProvider: React.FC<CurrencyProviderProps> = ({ 
  children, 
  defaultCurrency = 'EUR' 
}) => {
  const [currency, setCurrencyState] = useState<Currency>(() => {
    try {
      const saved = localStorage.getItem('preferred_currency');
      return (saved as Currency) || defaultCurrency;
    } catch (error) {
      return defaultCurrency;
    }
  });
  
  const [rates, setRates] = useState<ExchangeRates>({});
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const loadExchangeRates = async () => {
      setIsLoading(true);
      try {
        // Clear cache to force fresh rates
        localStorage.removeItem('exchange_rates');
        const exchangeRates = await CurrencyService.getExchangeRates();
        setRates(exchangeRates);
        console.log('Exchange rates loaded:', exchangeRates);
      } catch (error) {
        console.error('Failed to load exchange rates:', error);
        // Use fallback rates with corrected values
        setRates({
          EUR: 1,
          USD: 1.08,
          MAD: 10.95, // 1 EUR = 10.95 MAD
          DZD: 145.50, // 1 EUR = 145.50 DZD  
          TND: 3.35, // 1 EUR = 3.35 TND
        });
      } finally {
        setIsLoading(false);
      }
    };

    // Load rates immediately
    loadExchangeRates();
  }, []);

  const setCurrency = (newCurrency: Currency) => {
    setCurrencyState(newCurrency);
    try {
      localStorage.setItem('preferred_currency', newCurrency);
    } catch (error) {
      console.warn('Failed to save currency preference:', error);
    }
  };

  const convertPrice = (amount: number, fromCurrency: Currency = 'EUR'): number => {
    return CurrencyService.convertPrice(amount, fromCurrency, currency, rates);
  };

  const formatPrice = (amount: number, fromCurrency: Currency = 'EUR'): string => {
    const convertedAmount = convertPrice(amount, fromCurrency);
    const options: CurrencyFormatOptions = {
      currency,
      locale: CURRENCY_LOCALES[currency],
      symbol: CURRENCY_SYMBOLS[currency],
    };
    return CurrencyService.formatPrice(convertedAmount, options);
  };

  const getCurrencySymbol = (): string => {
    return CURRENCY_SYMBOLS[currency];
  };

  return (
    <CurrencyContext.Provider 
      value={{
        currency,
        setCurrency,
        rates,
        convertPrice,
        formatPrice,
        getCurrencySymbol,
        isLoading,
      }}
    >
      {children}
    </CurrencyContext.Provider>
  );
};

export const useCurrency = (): CurrencyContextType => {
  const context = useContext(CurrencyContext);
  if (context === undefined) {
    throw new Error('useCurrency must be used within a CurrencyProvider');
  }
  return context;
};