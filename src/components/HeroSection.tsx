import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";
import heroBackground from "@/assets/hero-background.jpg";

const HeroSection = () => {
  const { t } = useLanguage();
  
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section 
      id="hero" 
      className="relative min-h-screen flex items-center justify-center bg-cover bg-center bg-no-repeat overflow-hidden"
      style={{ backgroundImage: `url(${heroBackground})` }}
    >
      {/* Enhanced Overlay for better contrast */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-900/70 via-slate-900/60 to-slate-900/70 backdrop-blur-sm"></div>
      
      {/* Subtle background animated shapes */}
      <div className="absolute top-20 left-10 w-72 h-72 bg-primary/10 rounded-full blur-3xl animate-float"></div>
      <div className="absolute bottom-20 right-10 w-96 h-96 bg-accent/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '1s' }}></div>
      
      {/* Content Container with Glassmorphism */}
      <div className="relative z-10 text-center text-white px-4 max-w-5xl mx-auto 
                    bg-white/5 backdrop-blur-lg rounded-2xl p-8 md:p-12 border border-white/10 shadow-2xl shadow-black/20">
        
        <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-md border border-white/20 rounded-full px-6 py-3 mb-8 animate-bounce-in">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          <span className="text-sm font-semibold text-slate-200">12,000+ professionnels formés • 97% de réussite</span>
        </div>

        <h1 className="text-5xl md:text-7xl lg:text-8xl font-heading font-black mb-6 leading-tight animate-fade-in text-shadow-hero text-slate-50">
          {t('hero.title')}<br />
          <span className="shimmer-gradient">
            {t('hero.subtitle')}
          </span>
        </h1>
        
        <p className="text-xl md:text-2xl lg:text-3xl mb-12 opacity-90 leading-relaxed animate-slide-up font-medium max-w-4xl mx-auto text-slate-200 text-shadow-hero">
          {t('hero.description')}
        </p>
        
        {/* CTA Group */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center animate-scale-in">
          <Button 
            size="lg"
            onClick={() => scrollToSection('offre-speciale')}
            className="bg-gradient-accent text-accent-foreground hover:opacity-95 font-bold px-10 py-5 text-xl rounded-full shadow-2xl hover:shadow-accent/50 transition-all duration-500 transform hover:scale-110 animate-pulse-glow min-w-[280px] border border-accent/50"
          >
            🚀 {t('hero.cta')}
          </Button>
          
          <Button 
            variant="outline"
            size="lg"
            onClick={() => scrollToSection('formations')}
            className="border-2 border-white/20 text-white hover:bg-white/10 hover:text-white font-semibold px-8 py-5 text-lg rounded-full backdrop-blur-md transition-all duration-300 min-w-[200px]"
          >
            Voir les formations
          </Button>
        </div>

        {/* Trust Indicators */}
        <div className="mt-16 flex flex-wrap justify-center items-center gap-8 opacity-90 animate-fade-in" style={{ animationDelay: '0.8s' }}>
          <div className="text-center">
            <div className="text-3xl font-bold text-accent">12,000+</div>
            <div className="text-sm text-slate-300">Étudiants</div>
          </div>
          <div className="w-px h-8 bg-white/20"></div>
          <div className="text-center">
            <div className="text-3xl font-bold text-accent">97%</div>
            <div className="text-sm text-slate-300">Taux de réussite</div>
          </div>
          <div className="w-px h-8 bg-white/20"></div>
          <div className="text-center">
            <div className="text-3xl font-bold text-accent">6 mois</div>
            <div className="text-sm text-slate-300">Formation max</div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
