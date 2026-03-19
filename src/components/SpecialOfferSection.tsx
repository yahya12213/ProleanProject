import { Button } from "@/components/ui/button";
import CountdownTimer from "./CountdownTimer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useCurrency } from "@/contexts/CurrencyContext";

const SpecialOfferSection = () => {
  const { t, isRTL } = useLanguage();
  const { formatPrice } = useCurrency();

  return (
    <section id="offre-speciale" className="py-24 bg-gradient-to-br from-primary/5 via-background to-accent/5 relative overflow-hidden">
      {/* Animated Background */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(139,95,230,0.15),transparent_70%)]"></div>
      <div className="absolute top-0 right-0 w-96 h-96 bg-accent/10 rounded-full blur-3xl animate-float"></div>
      <div className="absolute bottom-0 left-0 w-80 h-80 bg-primary/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '2s' }}></div>
      
      <div className="container mx-auto px-4 relative z-10">
        <div className={`grid md:grid-cols-2 gap-16 items-center ${isRTL ? 'md:grid-cols-2 md:grid-flow-col-dense' : ''}`}>
          {/* Text Content */}
          <div className={`${isRTL ? 'md:order-2' : ''} animate-slide-up`}>
            <div className="inline-flex items-center gap-3 bg-gradient-accent text-accent-foreground px-6 py-3 rounded-full text-sm font-bold mb-8 animate-pulse-glow">
              ⚡ {t('offer.limited')}
            </div>
            
            <h2 className="text-4xl md:text-6xl font-heading font-black text-foreground mb-8 leading-tight">
              {t('offer.title')}
            </h2>
            
            <p className="text-xl text-muted-foreground mb-10 leading-relaxed">
              {t('offer.description')}
            </p>
            
            {/* Enhanced Pricing */}
            <div className={`flex flex-col sm:flex-row sm:items-center gap-6 mb-10 ${isRTL ? 'sm:justify-end' : ''}`}>
              <div className="flex items-center gap-4">
                <span className="text-2xl text-muted-foreground line-through opacity-60">
                  {formatPrice(799)}
                </span>
                <span className="text-5xl font-black text-gradient bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                  {formatPrice(497)}
                </span>
              </div>
              
              <div className="bg-gradient-accent text-accent-foreground px-6 py-3 rounded-2xl shadow-strong">
                <div className="text-lg font-bold">{t('offer.discount')}</div>
                <div className="text-sm opacity-90">Économie de 302€</div>
              </div>
            </div>

            <div className="space-y-4 mb-10">
              <Button 
                size="lg"
                className="bg-gradient-accent text-accent-foreground hover:opacity-90 font-bold px-12 py-6 text-xl rounded-2xl shadow-strong hover:shadow-accent/50 transition-all duration-500 transform hover:scale-105 animate-bounce-in w-full sm:w-auto min-w-[320px]"
              >
                🚀 {t('offer.cta')}
              </Button>
              
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-accent rounded-full"></div>
                  <span>Paiement sécurisé</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-accent rounded-full"></div>
                  <span>Garantie 30 jours</span>
                </div>
              </div>
            </div>
            
            <div className="bg-gradient-card border border-white/20 rounded-2xl p-6 backdrop-blur-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-6 h-6 bg-accent rounded-full flex items-center justify-center">
                  <span className="text-accent-foreground text-sm font-bold">✓</span>
                </div>
                <span className="font-semibold text-foreground">{t('offer.guarantee')}</span>
              </div>
              <div className="text-sm text-muted-foreground ml-9">
                Plus de 2,340 étudiants nous font confiance
              </div>
            </div>
          </div>

          {/* Enhanced Countdown Timer */}
          <div className={`${isRTL ? 'md:order-1' : ''} animate-scale-in`} style={{ animationDelay: '0.3s' }}>
            <div className="bg-gradient-card backdrop-blur-lg border border-white/20 rounded-3xl p-8 shadow-strong">
              <div className="text-center mb-6">
                <h3 className="text-2xl font-heading font-bold text-foreground mb-2">
                  ⏰ Offre limitée
                </h3>
                <p className="text-muted-foreground">Cette offre expire bientôt</p>
              </div>
              
              <CountdownTimer />
              
              <div className="mt-8 space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Déjà inscrits aujourd'hui:</span>
                  <span className="font-bold text-accent">47 personnes</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Places restantes:</span>
                  <span className="font-bold text-destructive">13 places</span>
                </div>
                <div className="w-full bg-border rounded-full h-2 overflow-hidden">
                  <div className="bg-gradient-accent h-full w-[78%] rounded-full animate-pulse"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default SpecialOfferSection;