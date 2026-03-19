import { Button } from "@/components/ui/button";
import { Globe, ChevronDown } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { useCurrency } from "@/contexts/CurrencyContext";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Language, Currency } from "@/types/geography";

const LanguageSelector = () => {
  const { language, setLanguage, isRTL } = useLanguage();
  const { currency, setCurrency, getCurrencySymbol } = useCurrency();

  // Always include all three languages, regardless of country detection
  const allLanguages: Language[] = ['fr', 'en', 'ar'];

  const languageNames: Record<Language, string> = {
    fr: 'Français',
    en: 'English',
    ar: 'العربية',
  };

  const currencyNames: Record<Currency, string> = {
    EUR: 'Euro (€)',
    USD: 'US Dollar ($)',
    MAD: 'Dirham (DH)',
    DZD: 'Dinar (DA)',
    TND: 'Dinar (TND)',
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={`flex items-center gap-2 text-foreground hover:text-accent ${isRTL ? 'flex-row-reverse' : ''}`}
        >
          <Globe className="h-4 w-4" />
          <span className="font-medium">{language.toUpperCase()}</span>
          <span className="text-muted-foreground">|</span>
          <span className="font-medium">{getCurrencySymbol()}</span>
          <ChevronDown className="h-3 w-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align={isRTL ? "start" : "end"} className="min-w-[200px]">
        {/* Language Selection */}
        <div className="px-2 py-1 text-xs text-muted-foreground font-semibold uppercase tracking-wide">
          Language
        </div>
        {allLanguages.map((lang) => (
          <DropdownMenuItem
            key={lang}
            onClick={() => setLanguage(lang)}
            className={`flex items-center justify-between ${language === lang ? 'bg-accent/10' : ''}`}
          >
            <span>{languageNames[lang]}</span>
            {language === lang && <span className="text-accent">●</span>}
          </DropdownMenuItem>
        ))}
        
        <DropdownMenuSeparator />
        
        {/* Currency Selection */}
        <div className="px-2 py-1 text-xs text-muted-foreground font-semibold uppercase tracking-wide">
          Currency
        </div>
        {Object.entries(currencyNames).map(([curr, name]) => (
          <DropdownMenuItem
            key={curr}
            onClick={() => setCurrency(curr as Currency)}
            className={`flex items-center justify-between ${currency === curr ? 'bg-accent/10' : ''}`}
          >
            <span>{name}</span>
            {currency === curr && <span className="text-accent">●</span>}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export default LanguageSelector;