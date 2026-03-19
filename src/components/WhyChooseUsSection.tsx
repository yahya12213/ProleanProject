import { GraduationCap, Users, HandHeart } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";

const WhyChooseUsSection = () => {
  const { t, isRTL } = useLanguage();
  const features = [
    {
      icon: GraduationCap,
      title: t('whyUs.certifications.title'),
      description: t('whyUs.certifications.description')
    },
    {
      icon: Users,
      title: t('whyUs.experts.title'),
      description: t('whyUs.experts.description')
    },
    {
      icon: HandHeart,
      title: t('whyUs.support.title'),
      description: t('whyUs.support.description')
    }
  ];

  return (
    <section id="pourquoi-nous" className="py-24 bg-gradient-to-br from-neutral to-background relative overflow-hidden">
      {/* Background Patterns */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(129,90,213,0.1),transparent_50%)]"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,rgba(34,197,94,0.1),transparent_50%)]"></div>
      
      <div className="container mx-auto px-4 relative z-10">
        <div className="text-center mb-20">
          <div className="inline-flex items-center gap-2 bg-accent/10 text-accent px-4 py-2 rounded-full text-sm font-semibold mb-6">
            🏆 Méthode éprouvée
          </div>
          <h2 className="text-4xl md:text-6xl font-heading font-black text-foreground mb-6">
            {t('whyUs.title')}
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            {t('whyUs.subtitle')}
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <div 
              key={index} 
              className="group text-center bg-gradient-card backdrop-blur-sm border border-white/20 rounded-2xl p-8 hover:shadow-strong transition-all duration-500 hover:-translate-y-2 animate-slide-up"
              style={{ animationDelay: `${index * 0.3}s` }}
            >
              <div className="flex justify-center mb-6">
                <div className="relative p-6 bg-gradient-primary rounded-2xl shadow-glow group-hover:scale-110 transition-transform duration-300">
                  <feature.icon className="h-10 w-10 text-white" />
                  <div className="absolute inset-0 bg-gradient-primary rounded-2xl blur-xl opacity-50 group-hover:opacity-75 transition-opacity duration-300"></div>
                </div>
              </div>
              <h3 className="text-2xl font-heading font-bold text-foreground mb-4 group-hover:text-primary transition-colors">
                {feature.title}
              </h3>
              <p className="text-muted-foreground leading-relaxed text-lg">
                {feature.description}
              </p>
              
              {/* Stats */}
              <div className="mt-6 pt-6 border-t border-border/50">
                {index === 0 && <div className="text-accent font-bold text-lg">ISO 9001 certifié</div>}
                {index === 1 && <div className="text-accent font-bold text-lg">15+ ans d'expérience</div>}
                {index === 2 && <div className="text-accent font-bold text-lg">Support 24/7</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default WhyChooseUsSection;