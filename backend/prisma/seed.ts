import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  // --- Seed Superadmin ---
  const superadminEmail = 'superadmin@gmail.com';
  const superadminPassword = await bcrypt.hash('superadmin', 10);
  await prisma.user.upsert({
    where: { email: superadminEmail },
    update: {},
    create: {
      email: superadminEmail,
      password: superadminPassword,
      // Ajoutez ici les champs de rôle/permissions si le modèle User le permet
    },
  });
  console.log('Superadmin créé ou mis à jour.');
  console.log('Début du seeding...');

  // --- Seed pour les Formations ---
  const formationsData = [
    {
      slug: 'data-analyst',
      title: 'Digital Marketing',
      description: "Explorez les stratégies de marketing numérique, du SEO au marketing de contenu, pour accroître la visibilité et l'engagement.",
      imageUrl: '/src/assets/digital-marketing.jpg'
    }
  ];

  for (const formation of formationsData) {
    await prisma.formation.upsert({
      where: { slug: formation.slug },
      update: {},
      create: formation,
    });
  }
  console.log('Formations créées/mises à jour.');

  // --- Seed pour la FAQ ---
  const faqData = [
    {
      question: 'Quels sont les prérequis pour s\'inscrire ?',
      answer: 'Aucun prérequis n\'est nécessaire pour la plupart de nos formations. Cependant, certaines formations avancées peuvent nécessiter des connaissances de base dans le domaine concerné.',
      order: 1
    },
    {
      question: 'Comment se déroule le processus de certification ?',
      answer: 'Le processus de certification inclut la réussite des examens finaux de la formation, ainsi que la validation d\'un projet pratique supervisé par nos formateurs experts.',
      order: 2
    },
    {
      question: 'Proposez-vous des facilités de paiement ?',
      answer: 'Oui, nous proposons des plans de paiement flexibles et échelonnés pour vous permettre de financer votre formation en toute sérénité. Contactez-nous pour en savoir plus.',
      order: 3
    }
  ];

  for (const item of faqData) {
    await prisma.faq.create({
      data: item,
    });
  }
  console.log('FAQ créée.');

  console.log('Seeding terminé avec succès.');
}

main()
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
