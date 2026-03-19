import Header from "@/components/Header";
import HeroSection from "@/components/HeroSection";
import SpecialOfferSection from "@/components/SpecialOfferSection";
import FormationsSection from "@/components/FormationsSection";
import WhyChooseUsSection from "@/components/WhyChooseUsSection";
import TestimonialsSection from "@/components/TestimonialsSection";
import CertificationSection from "@/components/CertificationSection";
import FAQ from "@/components/FAQ";
import ContactSection from "@/components/ContactSection";
import Footer from "@/components/Footer";
import NotificationToast from "@/components/NotificationToast";

const Index = () => {
  return (
    <div className="min-h-screen">
      <Header />
      <HeroSection />
      <SpecialOfferSection />
      <FormationsSection />
      <WhyChooseUsSection />
      <TestimonialsSection />
      <FAQ />
      <CertificationSection />
      <ContactSection />
      <Footer />
      <NotificationToast />
    </div>
  );
};

export default Index;
