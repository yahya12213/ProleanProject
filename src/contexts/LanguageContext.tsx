
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Language, CountryConfig } from '@/types/geography';
import { GeolocationService } from '@/services/geolocation';
import { getCountryConfig } from '@/config/countries';

export interface LanguageContextType {
  language: Language;
  setLanguage: (language: Language) => void;
  availableLanguages: Language[];
  countryConfig: CountryConfig | null;
  isRTL: boolean;
  t: (key: string) => string;
  isDetecting: boolean;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

// NOTE: Les traductions pour les formations et FAQs ont été retirées
// car ces données sont maintenant chargées depuis l'API.
const translations = {
  fr: {
    // Navigation
    'nav.home': 'Accueil',
    'nav.offers': 'Offres',
    'nav.training': 'Formations',
    'nav.about': 'À propos',
    'nav.formations': 'Formations',
    'nav.certifications': 'Certifications',
    'nav.testimonials': 'Témoignages',
    'nav.contact': 'Contact',
    'nav.login': 'Connexion',

    // Hero Section
    'hero.title': 'Révolutionnez Votre Carrière',
    'hero.subtitle': 'En 6 Mois Seulement',
    'hero.description': 'Rejoignez les 12,000+ professionnels qui ont transformé leur vie grâce à nos formations ultra-pratiques. Des résultats concrets dès le premier jour.',
    'hero.cta': 'Découvrir nos offres',

    // Countdown
    'countdown.days': 'Jours',
    'countdown.hours': 'Heures',
    'countdown.minutes': 'Minutes',
    'countdown.seconds': 'Secondes',

    // Certifications
    'certifications.title': 'Nos Certifications',
    'certifications.subtitle': 'Des formations reconnues par les plus grandes organisations mondiales',
    
    // Special Offer
    'offer.limited': '🔥 DERNIÈRES 48H - OFFRE FLASH',
    'offer.title': 'Formation #1 Gestion de Projet',
    'offer.description': '97% de nos étudiants trouvent un emploi sous 90 jours. Formation intensive avec mentoring individuel et garantie emploi.',
    'offer.originalPrice': '799€',
    'offer.currentPrice': '497€',
    'offer.discount': '-38%',
    'offer.cta': 'Je M\'inscris et J\'économise 300€',
    'offer.guarantee': 'Accès à vie • Garantie satisfait ou remboursé 30 jours',
    
    // Formations Section
    'formations.title': 'Formations Ultra-Pratiques',
    'formations.subtitle': 'Résultats garantis en 6 mois maximum',
    'formations.cta': 'Découvrir la formation',
    
    // Why Choose Us Section  
    'whyUs.title': 'Pourquoi 97% Réussissent Avec Nous',
    'whyUs.subtitle': 'Notre méthode éprouvée depuis 2018',
    'whyUs.certifications.title': 'Des Formations Certifiantes Reconnues',
    'whyUs.certifications.description': 'Nos certifications sont validées par l\'industrie et vous donnent un avantage concurrentiel décisif sur le marché du travail.',
    'whyUs.experts.title': 'Experts Qualifiés',
    'whyUs.experts.description': 'Apprenez auprès de professionnels en activité qui partagent leur expérience terrain et leurs meilleures pratiques.',
    'whyUs.support.title': 'Suivi Personnalisé',
    'whyUs.support.description': 'Bénéficiez d\'un accompagnement individuel pour maximiser vos chances de réussite et d\'insertion professionnelle.',
    
    // Testimonials Section
    'testimonials.title': 'Ils ont transformé leur carrière avec PROLEAN',
    'testimonials.marie.name': 'Marie Dupont',
    'testimonials.marie.role': 'Chef de Projet Digital',
    'testimonials.marie.company': 'TechCorp',
    'testimonials.marie.content': 'Grâce à PROLEAN, **j\'ai décroché le poste de mes rêves en moins de 3 mois.** Le suivi personnalisé a fait toute la différence.',
    'testimonials.thomas.name': 'Thomas Martin',
    'testimonials.thomas.role': 'Data Analyst',
    'testimonials.thomas.company': 'DataVision',
    'testimonials.thomas.content': 'La formation était **exceptionnellement pratique et orientée résultats.** J\'ai pu appliquer immédiatement mes nouvelles compétences dans mon travail.',
    'testimonials.sophie.name': 'Sophie Bernard',
    'testimonials.sophie.role': 'Marketing Manager',
    'testimonials.sophie.company': 'BrandBoost',
    'testimonials.sophie.content': '**Une expérience de formation transformatrice !** Les formateurs sont des experts reconnus qui partagent généreusement leur expertise.',
    'testimonials.at': 'chez',
    
    // Contact Section
    'contact.title': 'Une question? Contactez-nous.',
    'contact.name': 'Votre nom',
    'contact.email': 'Votre e-mail',
    'contact.message': 'Votre message',
    'contact.privacy': 'Nous respectons votre vie privée. Pas de spam.',
    'contact.send': 'Envoyer mon message',
    'contact.info.title': 'Nos Coordonnées',
    'contact.info.address': 'Adresse',
    'contact.info.addressText': '123 Avenue de la Formation\n75001 Paris, France',
    'contact.info.phone': 'Téléphone',
    'contact.info.phoneText': '+33 1 23 45 67 89',
    'contact.info.email': 'E-mail',
    'contact.info.emailText': 'contact@prolean-formation.fr',
    'contact.successMessage': 'Merci pour votre message ! Nous vous répondrons rapidement.',
    
    // Footer
    'footer.description': 'Votre partenaire de confiance pour des formations certifiantes de qualité. Transformez votre carrière avec nos experts qualifiés.',
    'footer.quickLinks': 'Liens utiles',
    'footer.formations': 'Nos formations',
    'footer.certification': 'Certification',
    'footer.support': 'Support',
    'footer.blog': 'Blog',
    'footer.legal': 'Légal',
    'footer.privacy': 'Politique de confidentialité',
    'footer.terms': 'Conditions d\'utilisation',
    'footer.mentions': 'Mentions légales',
    'footer.cgv': 'CGV',
    'footer.copyright': '© 2025 PROLEAN Formation. Tous droits réservés.',
    
    // FAQ
    'faq.title': 'Questions Fréquemment Posées',
    'faq.subtitle': 'Trouvez des réponses à vos questions les plus courantes',

    // Registration
    'registration.title': 'Inscription à la Formation',
    'registration.subtitle': 'Inscrivez-vous pour',
    'registration.firstName': 'Prénom',
    'registration.lastName': 'Nom',
    'registration.email': 'Email',
    'registration.phone': 'Téléphone',
    'registration.company': 'Entreprise (optionnel)',
    'registration.experience': 'Niveau d\'expérience',
    'registration.motivation': 'Motivation / Objectifs',
    'registration.paymentMethod': 'Mode de paiement',
    'registration.selectExperience': 'Sélectionnez votre niveau',
    'registration.selectPayment': 'Choisissez votre mode de paiement',
    'registration.beginner': 'Débutant',
    'registration.intermediate': 'Intermédiaire',
    'registration.advanced': 'Avancé',
    'registration.creditCard': 'Carte bancaire',
    'registration.bankTransfer': 'Virement bancaire',
    'registration.installment': 'Paiement en plusieurs fois',
    'registration.motivationPlaceholder': 'Décrivez vos objectifs et motivations...',
    'registration.submit': 'Confirmer l\'inscription',
    'registration.success': 'Inscription réussie !',
    'registration.successDescription': 'Votre inscription a été enregistrée. Vous recevrez un email de confirmation.',
    'registration.error': 'Erreur d\'inscription',
    'registration.errorDescription': 'Une erreur s\'est produite. Veuillez réessayer.',
    
    // Notifications
    'notifications.welcome': 'Bienvenue chez PROLEAN !',
    'notifications.welcomeDescription': 'Découvrez nos formations professionnelles de qualité.',
    'notifications.specialOffer': 'Offre Spéciale !',
    'notifications.specialOfferDescription': 'Profitez de -30% sur toutes nos formations jusqu\'à la fin du mois.',
    
    // Common
    'common.cancel': 'Annuler',
    'common.close': 'Fermer',
    'common.save': 'Enregistrer',
    'common.edit': 'Modifier',
    'common.delete': 'Supprimer',
    'common.confirm': 'Confirmer',
    'common.loading': 'Chargement...',
    
    // Certification
    'certification.title': 'Vérification de Certificat',
    'certification.placeholder': 'Entrez votre numéro de certificat',
    'certification.verify': 'Vérifier',
    'certification.description': 'Entrez votre numéro de certificat pour vérifier son authenticité',
  },
  en: {
    // Similar structure, keys removed for brevity...
  },
  ar: {
    // Similar structure, keys removed for brevity...
  }
};

interface LanguageProviderProps {
  children: ReactNode;
  defaultLanguage?: Language;
}

export const LanguageProvider: React.FC<LanguageProviderProps> = ({ 
  children, 
  defaultLanguage 
}) => {
  const [language, setLanguageState] = useState<Language>(() => {
    try {
      const saved = localStorage.getItem('preferred_language');
      return (saved as Language) || defaultLanguage || 'fr';
    } catch (error) {
      return defaultLanguage || 'fr';
    }
  });
  
  const [countryConfig, setCountryConfig] = useState<CountryConfig | null>(null);
  const [isDetecting, setIsDetecting] = useState(false);

  useEffect(() => {
    const detectUserPreferences = async () => {
      setIsDetecting(true);
      try {
        const locationData = await GeolocationService.detectUserLocation();
        if (locationData) {
          const config = getCountryConfig(locationData.countryCode);
          setCountryConfig(config);
          const hasManualLanguageChoice = localStorage.getItem('preferred_language');
          if (!hasManualLanguageChoice && !defaultLanguage) {
            setLanguageState(config.defaultLanguage);
          }
        }
      } catch (error) {
        console.warn('Failed to detect user preferences:', error);
        setCountryConfig(getCountryConfig('DEFAULT'));
      } finally {
        setIsDetecting(false);
      }
    };
    const timer = setTimeout(detectUserPreferences, 100);
    return () => clearTimeout(timer);
  }, [defaultLanguage]);

  const setLanguage = (newLanguage: Language) => {
    setLanguageState(newLanguage);
    try {
      localStorage.setItem('preferred_language', newLanguage);
    } catch (error) {
      console.warn('Failed to save language preference:', error);
    }
    if (typeof document !== 'undefined') {
      document.documentElement.dir = newLanguage === 'ar' ? 'rtl' : 'ltr';
      document.documentElement.lang = newLanguage;
    }
  };

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
      document.documentElement.lang = language;
    }
  }, [language]);

  const availableLanguages = countryConfig?.languages || ['fr', 'en'];
  const isRTL = language === 'ar';

  const t = (key: string): string => {
    // Fallback logic to prevent crashes if a key is missing in a given language
    const langTranslations = translations[language] || translations['fr'];
    return langTranslations[key] || key;
  };

  return (
    <LanguageContext.Provider 
      value={{ 
        language, 
        setLanguage, 
        availableLanguages,
        countryConfig,
        isRTL,
        t,
        isDetecting,
      }}
    >
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = (): LanguageContextType => {
  const context = useContext(LanguageContext);
  if (context === undefined) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
};